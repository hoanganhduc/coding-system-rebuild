#!/usr/bin/env python3
"""Fail-closed immutable-release installer for grok-proxy.

The installer owns one coherent user/root release identity.  Release trees are
immutable, selectors switch only while a durable root-owned deny record exists,
and both the user command and fixed privileged broker path are small generated
gates which verify the selected release before executing it.

The module performs no privilege escalation.  A live ``--apply`` therefore has
to be invoked by root (normally through sudo); prefix-backed test installs run as
the current user and never touch live paths.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import secrets
import shutil
import signal
import selectors
import stat
import subprocess
import sys
import time
from typing import Callable, Iterable, Mapping, NamedTuple
import uuid


SCHEMA_VERSION = 2
CONTROL_SCHEMA_VERSION = 1
EVIDENCE_SCHEMA_VERSION = 3
RUNG_CANARY_SCHEMA_VERSION = 4
CANARY_TERMINAL_SCHEMA_VERSION = 1
RUNG_TRANSCRIPT_SCHEMA_VERSION = 2
RUNG_EVIDENCE_SCHEMA_VERSION = 6
QUALIFICATION_RESULT_SCHEMA_VERSION = 3
RELEASE_QUALIFICATION_SCHEMA_VERSION = 2
RUNG_CANARY_TIMEOUT_SECONDS = 900
QUALIFICATION_CLEANUP_RESERVE_SECONDS = 120
QUALIFICATION_TERMINAL_RESERVE_SECONDS = 5
QUALIFICATION_CONTAINMENT_RESERVE_SECONDS = 5
GATE_SMOKE_CONTAINMENT_SECONDS = 5
MAX_SWITCH_INVENTORY_ENTRIES = 8_192
MAX_SWITCH_QUIESCENCE_INVENTORY_ENTRIES = 32_768
MAX_SWITCH_INVENTORY_BYTES = 16 * 1024 * 1024
MAX_SWITCH_PROC_RECORD_BYTES = 128 * 1024
RUNNER_CGROUP_MAX_DEPTH = 32
RUNNER_CGROUP_MAX_DESCENDANTS = 1_024
RUNNER_CGROUP_CLEANUP_MAX_DEPTH = 256
RUNNER_CGROUP_REQUIRED_CONTROLLERS = frozenset({"cpu", "memory", "pids"})
RUNNER_CGROUP_LIMIT_FILES = (
    "cgroup.max.depth",
    "cgroup.max.descendants",
    "cpu.max",
    "memory.high",
    "memory.max",
    "memory.swap.max",
    "pids.max",
)
RUNNER_CGROUP_OPTIONAL_LIMIT_FILES = (
    "cpu.idle",
    "cpu.max.burst",
    "cpu.uclamp.max",
    "cpu.uclamp.min",
    "cpu.weight",
    "memory.swap.high",
    "memory.zswap.max",
)
RUNNER_CGROUP_LIMIT_WRITE_ORDER = (
    "cgroup.max.depth",
    "cgroup.max.descendants",
    "cpu.max",
    "cpu.max.burst",
    "cpu.uclamp.max",
    "cpu.uclamp.min",
    "cpu.weight",
    "cpu.idle",
    "memory.max",
    "memory.high",
    "memory.swap.max",
    "memory.swap.high",
    "memory.zswap.max",
    "pids.max",
)
QUALIFICATION_WORK_TIMEOUT_SECONDS = (
    RUNG_CANARY_TIMEOUT_SECONDS
    - QUALIFICATION_CLEANUP_RESERVE_SECONDS
    - QUALIFICATION_TERMINAL_RESERVE_SECONDS
    - QUALIFICATION_CONTAINMENT_RESERVE_SECONDS
)
BOOT_INVENTORY_SCHEMA_VERSION = 1
HANDSHAKE_PROTOCOL = 1
DIRECT_ADMISSION_RUNTIME = "grok_ms/release_admission.py"
GROK_SELF_ADMISSION_BLOCK = b'''RELEASE_ADMITTED=0
self_admit_release(){
  (( RELEASE_ADMITTED == 0 )) || return 0
  local control=/var/lib/grok-proxy/release-control
  if [[ "${GROK_TESTING:-0}" == 1 && -n "${GROK_TEST_ROOT_RELEASE_CONTROL:-}" ]]; then
    control="$GROK_TEST_ROOT_RELEASE_CONTROL"
  fi
  exec {GROK_SELF_RELEASE_LOCK_FD}<"$control/install.lock" \\
    || return 78
  local -a admission=(
    /usr/bin/python3 -I "$DIR/grok_ms/release_admission.py"
    "$DIR" "$SELF" "$GROK_SELF_RELEASE_LOCK_FD"
  )
  if (( RELEASE_CANARY == 1 )); then
    admission+=("$GROK_RELEASE_CANARY_FD")
  elif (( $# == 1 )) && [[ "$1" == recover ]]; then
    admission+=(--public-recovery)
  fi
  if ! "${admission[@]}"; then
    exec {GROK_SELF_RELEASE_LOCK_FD}<&-
    return 78
  fi
  RELEASE_ADMITTED=1
  if [[ "${GROK_RELEASE_LOCK_FD:-}" =~ ^[0-9]+$ ]]; then
    exec {GROK_RELEASE_LOCK_FD}<&-
  fi
  unset GROK_RELEASE_LOCK_FD
}
'''
GROK_ORDINARY_ADMISSION_BLOCK = b'''require_installed_release(){
  self_admit_release "$@"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]] && ! require_installed_release "$@"; then
  printf '[egress] editable source tree is not executable; use ~/.local/bin/grok-remote\\n' >&2
  exit 78
fi
'''
EGRESS_ADMISSION_BLOCK = b'''require_frozen_egress_release(){
  local control=/var/lib/grok-proxy/release-control
  local -a admission
  local provider_command=0 provider_canary=0 canary_binding=0
  local canary_extra=0 rc=0 name
  if [[ "${GROK_TESTING:-0}" == 1 && -n "${GROK_TEST_ROOT_RELEASE_CONTROL:-}" ]]; then
    control="$GROK_TEST_ROOT_RELEASE_CONTROL"
  fi
  exec {EGRESS_SELF_RELEASE_LOCK_FD}<"$control/install.lock" \\
    || return 78
  admission=(/usr/bin/python3 -I "$EG_DIR/grok_ms/release_admission.py" \\
    "$EG_DIR" "$EG_DIR/egress.sh" "$EGRESS_SELF_RELEASE_LOCK_FD"
  )
  if [[ "${GROK_PROVIDER_MODE:-0}" == 1 && $# == 2 ]]; then
    case "$1" in
      provider-up|provider-next|provider-recover|provider-stop|provider-prove-empty)
        provider_command=1 ;;
    esac
  fi
  [[ -v GROK_RELEASE_CANARY_FD || -v GROK_RELEASE_CANARY_RELEASE_ID ]] \\
    && canary_binding=1
  for name in GROK_RELEASE_CANARY_MODE GROK_RELEASE_RUNG_CANARY \\
              GROK_RELEASE_CANARY_RUNG GROK_RELEASE_CANARY_ROUTE_PROFILE \\
              GROK_RELEASE_CANARY_CONTRACT GROK_RELEASE_CANARY_GROK_RELEASE \\
              GROK_RELEASE_CANARY_KIND GROK_RELEASE_CANARY_MODEL \\
              GROK_RELEASE_CANARY_NONCE; do
    [[ -v $name ]] && canary_extra=1
  done
  if (( canary_binding == 1 || canary_extra == 1 )); then
    (( provider_command == 1 )) \\
      && (( canary_binding == 1 && canary_extra == 0 )) \\
      && [[ "${GROK_RELEASE_CANARY_FD:-}" =~ ^[0-9]+$ ]] \\
      && (( GROK_RELEASE_CANARY_FD >= 3 )) \\
      && [[ "${GROK_RELEASE_CANARY_RELEASE_ID:-}" =~ ^[0-9a-f]{64}$ ]] \\
      || { exec {EGRESS_SELF_RELEASE_LOCK_FD}<&-; return 78; }
    admission+=("$GROK_RELEASE_CANARY_FD")
    provider_canary=1
  elif [[ "${GROK_HANDOFF_MODE:-0}" == 1 && $# == 1 \\
     && "$1" == compatibility-handoff ]]; then
    admission+=(--public-recovery)
  elif (( provider_command == 1 )) \\
       && [[ "$1" == provider-recover || "$1" == provider-prove-empty ]]; then
    admission+=(--public-recovery --provider-recovery)
  fi
  "${admission[@]}" || rc=$?
  if (( provider_command == 1 )); then
    exec {EGRESS_SELF_RELEASE_LOCK_FD}<&-
    if (( provider_canary == 1 )); then
      exec {GROK_RELEASE_CANARY_FD}<&-
    fi
    unset GROK_RELEASE_CANARY_FD GROK_RELEASE_CANARY_RELEASE_ID
  fi
  return "$rc"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]] && ! require_frozen_egress_release "$@"; then
  printf '[egress] editable source tree is not executable; use ~/.local/bin/grok-remote\\n' >&2
  exit 78
fi
'''
DIRECT_ADMISSION_MARKERS = {
    "grok-remote": (
        GROK_SELF_ADMISSION_BLOCK,
        GROK_ORDINARY_ADMISSION_BLOCK,
    ),
    "egress.sh": (EGRESS_ADMISSION_BLOCK,),
    DIRECT_ADMISSION_RUNTIME: (
        b"fcntl.flock(lock_fd, fcntl.LOCK_SH)",
        b"rollback-deny.json",
        b"selected-release.json",
    ),
}
DIRECT_ADMISSION_PRODUCTION_PATHS = (
    "grok-remote",
    "egress.sh",
    DIRECT_ADMISSION_RUNTIME,
)
DIRECT_ADMISSION_PRODUCTION_BUNDLES = frozenset(
    {
        (
            "d13255158cda0358cce9a905c8e882c89a5fb9c7ad5a226a5e704b6d0bc067b1",
            "2abf36c5277cf32bb0eb1780903f934f2b859782a5a5775d1d16fa43e0f27d0a",
            "ee7321b80ab62693d7e09d8a686e999feb127f421c3637bb07e7276d9e95a6aa",
        ),
        (
            "d13255158cda0358cce9a905c8e882c89a5fb9c7ad5a226a5e704b6d0bc067b1",
            "5d9a607cea7869f5f062cc559089aab5a7fc4546f7e2026f1a8b98cc985318d0",
            "ee7321b80ab62693d7e09d8a686e999feb127f421c3637bb07e7276d9e95a6aa",
        ),
        (
            "c4a3f51261b35e4351690845dec4bfcc69eb0d366bae6272f6d42ce3cd5bfa82",
            "ef85fb7aff2409b1ba0b27240f1af9f8ed0de2e8e8a277b690440bfaaed3dace",
            "58a4bfc527af8e51fe033cebe49e59802d916e020c8a469ad547a9303f68d77e",
        ),
    }
)
# Compatibility index for callers that enumerate the fixed path set.  Bundle
# admission below remains tuple-based so old/new component hybrids never pass.
DIRECT_ADMISSION_PRODUCTION_SHA256 = {
    relative: frozenset(bundle[index] for bundle in DIRECT_ADMISSION_PRODUCTION_BUNDLES)
    for index, relative in enumerate(DIRECT_ADMISSION_PRODUCTION_PATHS)
}
ACTIVE_RELEASE_MODE = 0o555
ARCHIVED_RELEASE_MODE = 0o500
RELEASE_ID_RE = re.compile(r"^[0-9a-f]{64}$")
RUN_ID_RE = re.compile(r"^[0-9a-f]{32}$")
RUNNER_SCOPE_NAME_RE = re.compile(r"^grok-installer-[0-9a-f]{24}$")
RUNNER_SCOPE_RECORD_RE = re.compile(r"^([0-9a-f]{24})\.json$")
RUNNER_SCOPE_TEMP_RE = re.compile(
    r"^\.(?P<target>[0-9a-f]{24}\.json)\.tmp-(?P<nonce>[0-9a-f]{32})$"
)
RUNNER_SCOPE_RECORD_VERSION = 2
PENDING_RUN_RE = re.compile(r"^pending-([0-9a-f]{32})\.json$")
QUALIFICATION_PENDING_RE = re.compile(
    r"^pending-qualification-(load32|fault-recovery|real-pair)\.json$"
)
ROOT_ROLES = frozenset({"broker", "vpngate", "relay", "sanitizer"})
ZERO_DIGEST = "0" * 64
EVIDENCE_CRITERIA = (
    "release-pair",
    "target-root-map",
    "legacy-root-migration",
    "compatibility-matrix",
    "broker-status-helper-map",
    "multi-root-inventory-empty",
)
RUNG_MEASUREMENT_FIELDS = frozenset(
    {
        "duration_ms",
        "fault_load_canary_verified",
        "host_limits_verified",
        "result_sha256",
        "post_repair_reconnect_cache_execution_units_verified",
        "shared_route",
        "teardown_clean",
        "transport_timing_verified",
        "two_sessions",
    }
)
QUALIFICATION_STEPS = ("load32", "fault-recovery")
QUALIFICATION_MODES = frozenset({*QUALIFICATION_STEPS, "real-pair"})
QUALIFICATION_FAILURE_CODES = {
    "load32": frozenset(
        {
            "load32-authorization", "load32-provenance", "load32-contract",
            "load32-baseline", "load32-spawn", "load32-ready",
            "load32-runtime-proof", "load32-overload", "load32-completion",
            "load32-resource", "load32-resource-cgroup-pids-peak",
            "load32-resource-cgroup-pids-highwater", "load32-resource-memory",
            "load32-resource-sampler", "load32-cleanup", "load32-internal",
        }
    ),
    "fault-recovery": frozenset(
        {
            "fault-recovery-authorization", "fault-recovery-provenance",
            "fault-recovery-contract", "fault-recovery-baseline",
            "fault-recovery-spawn", "fault-recovery-ready",
            "fault-recovery-runtime-proof", "fault-recovery-supervisor-loss",
            "fault-recovery-recovery", "fault-recovery-resource",
            "fault-recovery-resource-cgroup-pids-peak",
            "fault-recovery-resource-cgroup-pids-highwater",
            "fault-recovery-resource-memory", "fault-recovery-resource-sampler",
            "fault-recovery-cleanup", "fault-recovery-internal",
        }
    ),
    "real-pair": frozenset(
        {
            "real-pair-authorization", "real-pair-provenance",
            "real-pair-contract", "real-pair-baseline", "real-pair-spawn",
            "real-pair-ready", "real-pair-authority", "real-pair-pause",
            "real-pair-model-refresh", "real-pair-provider-fault",
            "real-pair-old-generation",
            "real-pair-repair", "real-pair-reconnect", "real-pair-resume",
            "real-pair-completion",
            "real-pair-runtime", "real-pair-cleanup", "real-pair-internal",
        }
    ),
}
QUALIFICATION_BLOCKED_CODES = {
    step: frozenset({f"{step}-blocked"}) for step in QUALIFICATION_FAILURE_CODES
}
QUALIFICATION_COMMON_FIELDS = frozenset(
    {
        "schema_version", "kind", "step", "release_id", "canary_nonce",
        "canary_kind", "rung", "route_profile", "contract_sha256", "grok_release_id",
        "model_id", "status", "started_unix_ns", "completed_unix_ns",
        "duration_ms", "observations", "error_code", "error_sha256",
    }
)
QUALIFICATION_OBSERVATION_FIELDS = {
    "load32": frozenset(
        {
            "clients_requested", "clients_completed", "active_rung",
            "shared_owner_epoch", "shared_generation", "shared_contract",
            "unique_leaders", "overload_rejected", "byte_path_verified",
            "host_limits_captured", "resource_gate_passed", "cleanup_proved",
            "ready_duration_ms", "detail_sha256", "host_limits_sha256",
            "resource_contract", "resource_observed",
        }
    ),
    "fault-recovery": frozenset(
        {
            "active_rung", "supervisor_loss_exact", "wrapper_failed_closed",
            "descendant_contained", "first_recovery_applied",
            "second_recovery_noop", "recovery_duration_ms",
            "resource_gate_passed", "cleanup_proved", "detail_sha256",
            "host_limits_sha256", "resource_contract", "resource_observed",
        }
    ),
    "real-pair": frozenset(
        {
            "sessions_requested", "sessions_completed", "active_rung",
            "model_id", "shared_owner_epoch", "shared_generation",
            "shared_contract", "independent_grok_units",
            "shared_leader_disabled", "leader_socket_count", "unique_session_ids",
            "outputs_valid", "exit_codes_zero", "cache_before_valid",
            "cache_during_valid", "cache_after_valid", "cache_identity_safe",
            "provider_fault_authenticated", "single_repair_observed",
            "clients_survived_repair", "reconnect_duration_ms",
            "transport_duration_ms", "cleanup_proved", "detail_sha256",
            "blocked_reason",
        }
    ),
}
QUALIFICATION_RESOURCE_CONTRACT_FIELDS = frozenset(
    {
        "expected_owned_processes", "max_owned_fds", "max_owned_threads",
        "max_owned_vmrss_kib", "max_owned_vmsize_kib",
        "max_cgroup_pids_delta", "max_cgroup_memory_delta_bytes",
        "post_pids_tolerance", "post_memory_tolerance_bytes",
    }
)
QUALIFICATION_RESOURCE_OBSERVED_FIELDS = frozenset(
    {
        "peak_owned_processes", "peak_owned_fds", "peak_owned_threads",
        "peak_owned_vmrss_kib", "peak_owned_vmsize_kib",
        "cgroup_pids_delta", "cgroup_memory_delta_bytes",
        "cgroup_pids_highwater_delta",
        "cgroup_memory_highwater_delta_bytes", "memory_event_delta_total",
        "pids_event_delta_total", "post_owned_processes", "post_owned_fds",
        "post_owned_threads", "post_owned_vmrss_kib",
        "post_owned_vmsize_kib", "post_pids_delta",
        "post_memory_delta_bytes",
    }
)
RESOURCE_COUNTER_MAX = (1 << 63) - 1


def _qualification_resource_contract(step: str) -> dict[str, int]:
    count = 32 if step == "load32" else 1
    mode = "load" if step == "load32" else "fault"
    return {
        "expected_owned_processes": 2 * count + 2 if mode == "load" else 5,
        "max_owned_fds": 256 + 40 * count,
        "max_owned_threads": 96 + 12 * count,
        "max_owned_vmrss_kib": 768 * 1024 + count * 96 * 1024,
        "max_owned_vmsize_kib": 4 * 1024 * 1024 + count * 512 * 1024,
        "max_cgroup_pids_delta": 48 + 6 * count,
        "max_cgroup_memory_delta_bytes": 768 * 1024 * 1024
        + count * 96 * 1024 * 1024,
        "post_pids_tolerance": 16,
        "post_memory_tolerance_bytes": 512 * 1024 * 1024,
    }


def _qualification_resource_shape_valid(observations: Mapping[str, object]) -> bool:
    contract = observations.get("resource_contract")
    observed = observations.get("resource_observed")
    digest = observations.get("host_limits_sha256")
    if (
        type(contract) is not dict
        or set(contract) != QUALIFICATION_RESOURCE_CONTRACT_FIELDS
        or type(observed) is not dict
        or set(observed) != QUALIFICATION_RESOURCE_OBSERVED_FIELDS
        or type(digest) is not str
        or RELEASE_ID_RE.fullmatch(digest) is None
        or any(
            type(value) is not int or not 0 <= value <= RESOURCE_COUNTER_MAX
            for value in contract.values()
        )
    ):
        return False
    signed = {"post_pids_delta", "post_memory_delta_bytes"}
    return all(
        type(value) is int
        and (
            -RESOURCE_COUNTER_MAX <= value <= RESOURCE_COUNTER_MAX
            if name in signed
            else 0 <= value <= RESOURCE_COUNTER_MAX
        )
        for name, value in observed.items()
    )


def _qualification_resource_proves(
    step: str, observations: Mapping[str, object]
) -> bool:
    if not _qualification_resource_shape_valid(observations):
        return False
    contract = observations["resource_contract"]
    observed = observations["resource_observed"]
    assert isinstance(contract, dict) and isinstance(observed, dict)
    expected = _qualification_resource_contract(step)
    return (
        contract == expected
        and observations.get("host_limits_sha256") != ZERO_DIGEST
        and observed["peak_owned_processes"] == expected["expected_owned_processes"]
        and observed["peak_owned_fds"] <= expected["max_owned_fds"]
        and observed["peak_owned_threads"] <= expected["max_owned_threads"]
        and observed["peak_owned_vmrss_kib"] <= expected["max_owned_vmrss_kib"]
        and observed["peak_owned_vmsize_kib"] <= expected["max_owned_vmsize_kib"]
        and observed["cgroup_pids_delta"] <= expected["max_cgroup_pids_delta"]
        and observed["cgroup_pids_highwater_delta"]
        <= expected["max_cgroup_pids_delta"]
        and observed["cgroup_memory_delta_bytes"]
        <= expected["max_cgroup_memory_delta_bytes"]
        and observed["cgroup_memory_highwater_delta_bytes"]
        <= expected["max_cgroup_memory_delta_bytes"]
        and observed["memory_event_delta_total"] == 0
        and observed["pids_event_delta_total"] == 0
        and all(
            observed[name] == 0
            for name in (
                "post_owned_processes", "post_owned_fds", "post_owned_threads",
                "post_owned_vmrss_kib", "post_owned_vmsize_kib",
            )
        )
        and observed["post_pids_delta"] <= expected["post_pids_tolerance"]
        and observed["post_memory_delta_bytes"]
        <= expected["post_memory_tolerance_bytes"]
    )
QUALIFICATION_FAKE_MODEL = "grok-4.5"
RUNG_RECORD_FIELDS = frozenset(
    {
        "contract_sha256",
        "evidence_sha256",
        "grok_release_id",
        "rung",
    }
)
RUNG_TOKEN_RE = re.compile(r"^(?:direct|iphone|vpn|home:[A-Za-z0-9._:+@-]{1,120})$")
ROUTE_PROFILE_RE = re.compile(
    r"^(?:direct|iphone|vpn|auto|auto-no-direct|home:[A-Za-z0-9._:+@-]{1,120})$"
)
GROK_RELEASE_RE = re.compile(r"^[A-Za-z0-9._:+@-]{1,128}$")
MODEL_ID_RE = re.compile(r"^[A-Za-z0-9._:+/@-]{1,128}$")
CANARY_ENV_BINDINGS = (
    "GROK_RELEASE_CANARY_MODE",
    "GROK_RELEASE_CANARY_FD",
    "GROK_RELEASE_CANARY_RELEASE_ID",
    "GROK_RELEASE_RUNG_CANARY",
    "GROK_RELEASE_CANARY_RUNG",
    "GROK_RELEASE_CANARY_ROUTE_PROFILE",
    "GROK_RELEASE_CANARY_CONTRACT",
    "GROK_RELEASE_CANARY_GROK_RELEASE",
    "GROK_RELEASE_CANARY_KIND",
    "GROK_RELEASE_CANARY_MODEL",
    "GROK_RELEASE_CANARY_NONCE",
)
CANARY_TEST_ENV = (
    "GROK_BIN",
    "GROK_BLOCKED_CC",
    "GROK_CONNECT_TIMEOUT_MS",
    "GROK_HOME",
    "GROK_MAX_CONTROL_CONNECTIONS",
    "GROK_MAX_FRONTEND_STREAMS",
    "GROK_MAX_LEASES",
    "GROK_MAX_PACKET_BYTES",
    "GROK_PRIVATE_PORTS",
    "GROK_PROBE_TIMEOUT_MS",
    "GROK_PROXY_PORT",
    "GROK_STABILITY_INTERVAL_MS",
    "GROK_STOP_TIMEOUT_MS",
    "GROK_STREAM_BUFFER_BYTES",
    "GROK_TEST_CURL_BIN",
    "GROK_TEST_IPHONE_STATE_DIR",
    "GROK_TEST_SKIP_WARM_HANDOFF",
    "GROK_TOTAL_BUFFER_BYTES",
    "GROK_TRANSITION_TIMEOUT_MS",
    "GROK_VPN_MAX_TRIES",
    "GROK_VPN_STABILITY_CHECKS",
    "GROK_WATCHDOG_INTERVAL_MS",
    "VPNGATE_COUNTRIES",
    "VPNGATE_PREFER",
)

# This is a closed declaration, not a suffix-based scan of the project tree.
# The grok_ms package is the one recursive runtime namespace; only Python source
# below it is admitted and links/cache artifacts are rejected or ignored below.
DECLARED_RUNTIME_REQUIRED = (
    "grok-remote",
    "egress.sh",
    "socks-netns.py",
    "vpngate-connect.sh",
    "sanitize.awk",
)
DECLARED_BROKER_CANDIDATES = ("vpn-broker", "vpn-broker.py")
DECLARED_PACKAGE_ROOT = "grok_ms"
EXCLUDED_PACKAGE_PARTS = frozenset({"__pycache__", "tests", "test"})

AFTER_DENY = "after-deny"
AFTER_ROOT_STAGE = "after-root-stage"
AFTER_ROOT_PUBLISH = "after-root-publish"
AFTER_USER_STAGE = "after-user-stage"
AFTER_USER_PUBLISH = "after-user-publish"
AFTER_ROOT_SELECTOR = "after-root-selector"
AFTER_CURRENT_SELECTOR = "after-user-selector"  # compatibility name
AFTER_BROKER_SELECTOR = "after-broker-selector"
AFTER_ENTRYPOINT_SELECTOR = "after-entrypoint-selector"
AFTER_USER_SELECTION_METADATA = "after-user-selection-metadata"
AFTER_SELECTION_METADATA = "after-root-selection-metadata"  # compatibility name
AFTER_CANARY_SELECTION = "after-canary-selection"
AFTER_EVIDENCE = "after-evidence"
AFTER_FINAL_SELECTION = "after-final-selection"
BEFORE_DENY_CLEAR = "before-deny-clear"
AFTER_DENY_CLEAR = "after-deny-clear"
AFTER_CANARY_UNLINK = "after-canary-unlink"

SELECTION_FAULT_STAGES = (
    AFTER_ROOT_SELECTOR,
    AFTER_CURRENT_SELECTOR,
    AFTER_BROKER_SELECTOR,
    AFTER_ENTRYPOINT_SELECTOR,
    AFTER_USER_SELECTION_METADATA,
    AFTER_SELECTION_METADATA,
    AFTER_CANARY_SELECTION,
    AFTER_EVIDENCE,
    AFTER_FINAL_SELECTION,
    BEFORE_DENY_CLEAR,
    AFTER_DENY_CLEAR,
)
INSTALL_FAULT_STAGES = (
    AFTER_DENY,
    AFTER_ROOT_STAGE,
    AFTER_ROOT_PUBLISH,
    AFTER_USER_STAGE,
    AFTER_USER_PUBLISH,
    *SELECTION_FAULT_STAGES,
)
ROLLBACK_FAULT_STAGES = (AFTER_DENY, *SELECTION_FAULT_STAGES)


class ReleaseError(RuntimeError):
    """A release operation could not prove that it was safe."""


class SessionContainmentError(ReleaseError):
    """An owned runner session could not be contained without PID reuse risk."""


class _SwitchInventoryBudget:
    """One fail-closed deadline and resource budget for a quiescence pass."""

    def __init__(self, deadline_monotonic_ns: int) -> None:
        if type(deadline_monotonic_ns) is not int or deadline_monotonic_ns <= 0:
            raise ReleaseError("switch inventory deadline is invalid")
        self.deadline_monotonic_ns = deadline_monotonic_ns
        self.entries_remaining = MAX_SWITCH_QUIESCENCE_INVENTORY_ENTRIES
        self.bytes_remaining = MAX_SWITCH_INVENTORY_BYTES

    def check(self, operation: str) -> None:
        if time.monotonic_ns() >= self.deadline_monotonic_ns:
            raise ReleaseError(f"timed out during switch {operation}")

    def consume_entry(self, operation: str) -> None:
        self.check(operation)
        if self.entries_remaining <= 0:
            raise ReleaseError("switch inventory entry limit exceeded")
        self.entries_remaining -= 1

    def consume_bytes(self, count: int, operation: str) -> None:
        self.check(operation)
        if count < 0 or count > self.bytes_remaining:
            raise ReleaseError("switch inventory byte limit exceeded")
        self.bytes_remaining -= count

    def read_at(
        self,
        directory_fd: int,
        name: str,
        maximum: int,
        operation: str,
    ) -> bytes:
        if maximum <= 0:
            raise ReleaseError("switch inventory record bound is invalid")
        self.check(operation)
        descriptor = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
        try:
            data = bytearray()
            while len(data) <= maximum:
                self.check(operation)
                chunk = os.read(
                    descriptor,
                    min(16_384, maximum + 1 - len(data)),
                )
                if not chunk:
                    break
                self.consume_bytes(len(chunk), operation)
                data.extend(chunk)
            if len(data) > maximum:
                raise ReleaseError(f"oversized switch inventory record: {name}")
            return bytes(data)
        finally:
            os.close(descriptor)

    def read_path(self, path: Path, maximum: int, operation: str) -> bytes:
        parent = os.open(
            path.parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            return self.read_at(parent, path.name, maximum, operation)
        finally:
            os.close(parent)


class InjectedFault(ReleaseError):
    """A deterministic simulated interruption at a semantic stage."""

    def __init__(self, stage: str):
        super().__init__(f"injected fault at {stage}")
        self.stage = stage


def _pidfd_exit_ready(pidfd: int, timeout: float) -> bool:
    with selectors.DefaultSelector() as selector:
        selector.register(pidfd, selectors.EVENT_READ)
        return bool(selector.select(max(0.0, timeout)))


class _QuarantinedSession(NamedTuple):
    process: subprocess.Popen[bytes]
    leader_pidfd: int


_QUARANTINED_SESSIONS: list[_QuarantinedSession] = []


def _quarantine_session(
    process: subprocess.Popen[bytes], leader_pidfd: int
) -> None:
    """Keep an unreaped leader pinned after an uncertain group kill."""

    if any(item.process is process for item in _QUARANTINED_SESSIONS):
        return
    retained_pidfd = -1
    if leader_pidfd >= 0:
        try:
            retained_pidfd = fcntl.fcntl(
                leader_pidfd, fcntl.F_DUPFD_CLOEXEC, 0
            )
        except OSError:
            # Retaining the Popen object still prevents its destructor from
            # reaping an exited leader and freeing the PGID during this run.
            retained_pidfd = -1
    _QUARANTINED_SESSIONS.append(
        _QuarantinedSession(process, retained_pidfd)
    )


def _session_is_quarantined(process: subprocess.Popen[bytes]) -> bool:
    return any(item.process is process for item in _QUARANTINED_SESSIONS)


def _kill_session_group_before_reap(
    process: subprocess.Popen[bytes],
    leader_pidfd: int,
    *,
    graceful_seconds: float,
    kill_seconds: float = 5.0,
    deadline_monotonic_ns: int | None = None,
) -> int:
    """Terminate one owned session while its leader PID still pins the PGID."""

    if process.returncode is not None:
        raise ReleaseError("session leader was reaped before group containment")
    def remaining(maximum: float) -> float:
        if deadline_monotonic_ns is None:
            return max(0.0, maximum)
        return max(
            0.0,
            min(
                maximum,
                (deadline_monotonic_ns - time.monotonic_ns())
                / 1_000_000_000,
            ),
        )

    leader_exited = _pidfd_exit_ready(
        leader_pidfd, remaining(graceful_seconds)
    )
    group_error: OSError | None = None
    while True:
        try:
            os.killpg(process.pid, signal.SIGKILL)
            break
        except InterruptedError:
            continue
        except ProcessLookupError as exc:
            if not leader_exited:
                group_error = exc
            break
        except OSError as exc:
            group_error = exc
            break
    if group_error is not None:
        _quarantine_session(process, leader_pidfd)
        raise SessionContainmentError(
            f"cannot terminate exact session group before reap: {group_error}"
        ) from group_error
    if not leader_exited:
        leader_exited = _pidfd_exit_ready(
            leader_pidfd, remaining(kill_seconds)
        )
    if not leader_exited and hasattr(signal, "pidfd_send_signal"):
        try:
            signal.pidfd_send_signal(leader_pidfd, signal.SIGKILL)
        except ProcessLookupError:
            pass
        leader_exited = _pidfd_exit_ready(
            leader_pidfd, remaining(kill_seconds)
        )
    if not leader_exited:
        _quarantine_session(process, leader_pidfd)
        raise SessionContainmentError(
            "session leader did not exit after exact group termination"
        )
    try:
        returncode = process.wait(timeout=remaining(1.0))
    except subprocess.TimeoutExpired as exc:
        _quarantine_session(process, leader_pidfd)
        raise SessionContainmentError(
            "session leader could not be reaped after pidfd exit"
        ) from exc
    return returncode


def _kill_session_group_without_pidfd_before_reap(
    process: subprocess.Popen[bytes],
    *,
    deadline_monotonic_ns: int | None = None,
) -> int:
    """Fail closed if pidfd acquisition failed after creating a session."""

    if process.returncode is not None:
        raise ReleaseError("session leader was reaped before group containment")
    while True:
        try:
            os.killpg(process.pid, signal.SIGKILL)
            break
        except InterruptedError:
            continue
        except ProcessLookupError:
            # A missing group cannot contain a same-PGID descendant.  The
            # still-unreaped Popen object pins any exited leader until wait().
            break
        except OSError as exc:
            _quarantine_session(process, -1)
            raise SessionContainmentError(
                f"cannot terminate unanchored session group before reap: {exc}"
            ) from exc
    try:
        timeout = 5.0
        if deadline_monotonic_ns is not None:
            timeout = max(
                0.0,
                min(
                    timeout,
                    (deadline_monotonic_ns - time.monotonic_ns())
                    / 1_000_000_000,
                ),
            )
        return process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        _quarantine_session(process, -1)
        raise SessionContainmentError(
            "unanchored session leader could not be reaped after group kill"
        ) from exc


def _reap_after_cgroup_cleanup(
    process: subprocess.Popen[bytes],
    leader_pidfd: int,
    *,
    deadline_monotonic_ns: int,
) -> int:
    """Reap a leader only after its exact descendant cgroup proved empty."""

    remaining = max(
        0.0,
        (deadline_monotonic_ns - time.monotonic_ns()) / 1_000_000_000,
    )
    if leader_pidfd >= 0 and not _pidfd_exit_ready(leader_pidfd, remaining):
        _quarantine_session(process, leader_pidfd)
        raise SessionContainmentError(
            "installer runner leader remained live after cgroup cleanup"
        )
    try:
        return process.wait(
            timeout=max(
                0.0,
                (deadline_monotonic_ns - time.monotonic_ns())
                / 1_000_000_000,
            )
        )
    except subprocess.TimeoutExpired as exc:
        _quarantine_session(process, leader_pidfd)
        raise SessionContainmentError(
            "installer runner leader could not be reaped after cgroup cleanup"
        ) from exc


class _RunnerCgroupPlacement(NamedTuple):
    parent: Path
    parent_info: os.stat_result
    source: Path
    source_info: os.stat_result
    source_cpu_affinity: tuple[int, ...]
    effective_limits: Mapping[str, str]


def _runner_cgroup_control(
    cgroup: Path,
    name: str,
    *,
    maximum: int = 4096,
) -> bytes:
    """Read one bounded, non-link cgroup control from an anchored hierarchy."""

    path = cgroup / name
    try:
        before = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(before.st_mode):
            raise ReleaseError(f"installer cgroup-v2 control is unsafe: {path}")
        raw = path.read_bytes()
        after = path.lstat()
    except OSError as exc:
        raise ReleaseError(
            f"cannot inspect installer cgroup-v2 control {path}: {exc}"
        ) from exc
    if (
        len(raw) > maximum
        or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
    ):
        raise ReleaseError(f"installer cgroup-v2 control changed or is oversized: {path}")
    return raw


def _runner_effective_limits(current: Path, mount: Path) -> dict[str, str]:
    """Fold the caller's effective limits so a sibling runner cannot escape them."""

    scalar_names = (
        "cgroup.max.depth",
        "cgroup.max.descendants",
        "memory.high",
        "memory.max",
        "memory.swap.max",
        "pids.max",
    )
    optional_scalar_names = tuple(
        name
        for name in ("cpu.max.burst", "memory.swap.high", "memory.zswap.max")
        if (current / name).exists()
    )
    uclamp_names = tuple(
        name
        for name in ("cpu.uclamp.max", "cpu.uclamp.min")
        if (current / name).exists()
    )
    scalar_values: dict[str, list[int]] = {
        name: [] for name in (*scalar_names, *optional_scalar_names)
    }
    uclamp_values: dict[str, list[int]] = {name: [] for name in uclamp_names}
    uclamp_saw_max = {name: False for name in uclamp_names}
    cpu_values: list[tuple[int, int]] = []
    current_cpu_max = "max 100000"
    candidate = current
    first = True
    ancestor_distance = 0
    while candidate != mount:
        for name in scalar_values:
            try:
                raw = _runner_cgroup_control(candidate, name, maximum=128)
            except ReleaseError as exc:
                raise ReleaseError(
                    f"cannot preserve the caller's effective {name} limit"
                ) from exc
            try:
                value = raw.decode("ascii").strip()
            except UnicodeError as exc:
                raise ReleaseError(
                    f"installer cgroup-v2 {name} limit is non-ASCII"
                ) from exc
            if value != "max":
                if not value.isdecimal():
                    raise ReleaseError(
                        f"installer cgroup-v2 {name} limit is invalid"
                    )
                numeric = int(value)
                if name == "cgroup.max.depth":
                    numeric = max(0, numeric - ancestor_distance)
                scalar_values[name].append(numeric)

        for name in uclamp_names:
            try:
                raw = _runner_cgroup_control(candidate, name, maximum=128)
                value = raw.decode("ascii").strip()
            except (ReleaseError, UnicodeError) as exc:
                raise ReleaseError(
                    f"cannot preserve the caller's effective {name} limit"
                ) from exc
            if value == "max":
                if name.endswith(".min"):
                    uclamp_values[name].append(10_000)
                else:
                    uclamp_saw_max[name] = True
                continue
            match = re.fullmatch(r"([0-9]{1,3})(?:\.([0-9]{1,2}))?", value)
            if match is None:
                raise ReleaseError(f"installer cgroup-v2 {name} limit is invalid")
            whole = int(match.group(1))
            fraction = (match.group(2) or "").ljust(2, "0")
            hundredths = whole * 100 + int(fraction or "0")
            if hundredths > 10_000:
                raise ReleaseError(f"installer cgroup-v2 {name} limit is invalid")
            uclamp_values[name].append(hundredths)

        try:
            cpu_raw = _runner_cgroup_control(candidate, "cpu.max", maximum=128)
            cpu_fields = cpu_raw.decode("ascii").split()
        except (ReleaseError, UnicodeError) as exc:
            raise ReleaseError(
                "cannot preserve the caller's effective cpu.max limit"
            ) from exc
        if (
            len(cpu_fields) != 2
            or not cpu_fields[1].isdecimal()
            or int(cpu_fields[1]) <= 0
            or not (cpu_fields[0] == "max" or cpu_fields[0].isdecimal())
        ):
            raise ReleaseError("installer cgroup-v2 cpu.max limit is invalid")
        if first:
            current_cpu_max = " ".join(cpu_fields)
            first = False
        if cpu_fields[0] != "max":
            quota = int(cpu_fields[0])
            period = int(cpu_fields[1])
            if quota <= 0:
                raise ReleaseError("installer cgroup-v2 cpu.max quota is invalid")
            cpu_values.append((quota, period))
        candidate = candidate.parent
        ancestor_distance += 1

    limits = {
        name: str(min(values)) if values else "max"
        for name, values in scalar_values.items()
    }
    for name, configured in (
        ("cgroup.max.depth", RUNNER_CGROUP_MAX_DEPTH),
        ("cgroup.max.descendants", RUNNER_CGROUP_MAX_DESCENDANTS),
    ):
        inherited = limits[name]
        limits[name] = str(
            min(configured, int(inherited))
            if inherited != "max"
            else configured
        )
    if cpu_values:
        rate_quota, rate_period = cpu_values[0]
        # A single child quota must preserve both the smallest sustained rate
        # and the smallest finite burst from every escaped caller ancestor.
        for candidate_quota, candidate_period in cpu_values:
            if candidate_quota * rate_period < rate_quota * candidate_period:
                rate_quota, rate_period = candidate_quota, candidate_period
        quota = min(item[0] for item in cpu_values)
        period = max(
            1_000,
            (quota * rate_period + rate_quota - 1) // rate_quota,
        )
        if period > 1_000_000:
            raise ReleaseError(
                "caller cpu.max envelope cannot be represented by one runner quota"
            )
        limits["cpu.max"] = f"{quota} {period}"
    else:
        limits["cpu.max"] = current_cpu_max
    for name, values in uclamp_values.items():
        if values:
            effective = min(values) if name.endswith(".max") else max(values)
            limits[name] = f"{effective // 100}.{effective % 100:02d}"
        elif uclamp_saw_max[name]:
            limits[name] = "max"
    for name, lower, upper in (
        ("cpu.weight", 1, 10_000),
        ("cpu.idle", 0, 1),
    ):
        if not (current / name).exists():
            continue
        try:
            value = _runner_cgroup_control(current, name, maximum=128).decode(
                "ascii"
            ).strip()
        except (ReleaseError, UnicodeError) as exc:
            raise ReleaseError(
                f"cannot preserve the caller's configured {name} value"
            ) from exc
        if not value.isdecimal() or not lower <= int(value) <= upper:
            raise ReleaseError(f"installer cgroup-v2 {name} value is invalid")
        limits[name] = value
    if not set(RUNNER_CGROUP_LIMIT_FILES) <= set(limits):
        raise AssertionError("installer runner effective limit set is incomplete")
    if not set(limits) <= set(RUNNER_CGROUP_LIMIT_FILES) | set(
        RUNNER_CGROUP_OPTIONAL_LIMIT_FILES
    ):
        raise AssertionError("installer runner effective limit set is unexpected")
    return limits


def _runner_cgroup_parent(
    target_uid: int,
    target_gid: int,
    *,
    proc_cgroup: Path = Path("/proc/self/cgroup"),
    mount: Path = Path("/sys/fs/cgroup"),
) -> _RunnerCgroupPlacement:
    """Return a target-owned delegated ancestor and caller-equivalent limits."""

    if target_uid < 1 or target_gid < 1:
        raise ReleaseError("installer runner target identity is invalid")

    try:
        raw_bytes = proc_cgroup.read_bytes()
        if len(raw_bytes) > 16_384:
            raise ReleaseError("installer cgroup membership record is oversized")
        raw = raw_bytes.decode("ascii")
        lines = raw.splitlines()
        if len(lines) != 1 or not lines[0].startswith("0::/"):
            raise ReleaseError("installer is not in one unified cgroup-v2 hierarchy")
        relative = lines[0][3:]
        if not relative.startswith("/") or ".." in Path(relative).parts:
            raise ReleaseError("installer cgroup path is not canonical")
        mount_info = mount.lstat()
        current = mount / relative.lstrip("/")
        current_info = current.lstat()
    except (OSError, UnicodeError) as exc:
        raise ReleaseError(f"cannot inspect installer cgroup-v2 parent: {exc}") from exc
    if (
        mount.is_symlink()
        or current.is_symlink()
        or not stat.S_ISDIR(mount_info.st_mode)
        or not stat.S_ISDIR(current_info.st_mode)
        or current_info.st_dev != mount_info.st_dev
    ):
        raise ReleaseError("installer cgroup-v2 parent has an unsafe identity")
    source_cpu_affinity = tuple(sorted(os.sched_getaffinity(0)))
    if not source_cpu_affinity:
        raise ReleaseError("installer source CPU affinity is empty")
    effective_limits = _runner_effective_limits(current, mount)
    candidates: list[Path] = []
    candidate = current
    user_slice: Path | None = None
    while candidate != mount:
        candidates.append(candidate)
        if candidate.name == f"user-{target_uid}.slice":
            user_slice = candidate
        candidate = candidate.parent
    if user_slice is not None:
        user_service = user_slice / f"user@{target_uid}.service"
        try:
            user_service.lstat()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise ReleaseError(
                f"cannot inspect target user service cgroup: {exc}"
            ) from exc
        else:
            if user_service not in candidates:
                candidates.append(user_service)

    for candidate in candidates:
        try:
            info = candidate.lstat()
            subtree = _runner_cgroup_control(
                candidate, "cgroup.subtree_control"
            )
            cgroup_type = _runner_cgroup_control(candidate, "cgroup.type", maximum=64)
        except (OSError, ReleaseError) as exc:
            raise ReleaseError(
                f"cannot inspect installer cgroup-v2 controller delegation: {exc}"
            ) from exc
        if (
            candidate.is_symlink()
            or not stat.S_ISDIR(info.st_mode)
            or info.st_dev != mount_info.st_dev
            or len(subtree) > 4096
            or len(cgroup_type) > 64
        ):
            raise ReleaseError("installer cgroup-v2 ancestor has an unsafe identity")
        try:
            controllers = set(subtree.decode("ascii").split())
            type_name = cgroup_type.decode("ascii").strip()
        except UnicodeError as exc:
            raise ReleaseError(
                "installer cgroup-v2 controller delegation is non-ASCII"
            ) from exc
        is_delegated_candidate = (
            type_name == "domain"
            and RUNNER_CGROUP_REQUIRED_CONTROLLERS <= controllers
            and (info.st_uid, info.st_gid) == (target_uid, target_gid)
        )
        if is_delegated_candidate:
            try:
                delegated = os.getxattr(
                    candidate,
                    "user.delegate",
                    follow_symlinks=False,
                )
            except OSError as exc:
                if exc.errno in {errno.ENODATA, errno.ENOTSUP}:
                    continue
                raise ReleaseError(
                    f"cannot inspect installer cgroup-v2 delegation marker: {exc}"
                ) from exc
            try:
                procs = _runner_cgroup_control(
                    candidate, "cgroup.procs", maximum=4096
                )
                procs_info = (candidate / "cgroup.procs").lstat()
                subtree_info = (candidate / "cgroup.subtree_control").lstat()
                final_raw = proc_cgroup.read_bytes()
                final_current_info = current.lstat()
                final_info = candidate.lstat()
            except (OSError, ReleaseError) as exc:
                raise ReleaseError(
                    f"cannot revalidate installer cgroup-v2 delegation: {exc}"
                ) from exc
            if (
                delegated != b"1"
                or procs.strip()
                or (procs_info.st_uid, procs_info.st_gid)
                != (target_uid, target_gid)
                or (subtree_info.st_uid, subtree_info.st_gid)
                != (target_uid, target_gid)
            ):
                continue
            if (
                final_raw != raw_bytes
                or tuple(sorted(os.sched_getaffinity(0)))
                != source_cpu_affinity
                or (final_current_info.st_dev, final_current_info.st_ino)
                != (current_info.st_dev, current_info.st_ino)
                or (final_info.st_dev, final_info.st_ino)
                != (info.st_dev, info.st_ino)
            ):
                raise ReleaseError(
                    "installer cgroup-v2 membership or delegation changed"
                )
            return _RunnerCgroupPlacement(
                candidate,
                info,
                current,
                current_info,
                source_cpu_affinity,
                effective_limits,
            )
    raise ReleaseError(
        "installer has no target-owned delegated cgroup-v2 parent with cpu, memory, and pids"
    )


def _runner_cgroup_read_at(descriptor: int, name: str, maximum: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    child = os.open(name, flags, dir_fd=descriptor)
    try:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(child, min(4096, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise SessionContainmentError(
                    f"oversized installer cgroup record: {name}"
                )
        return b"".join(chunks)
    finally:
        os.close(child)


def _runner_cgroup_write_at(descriptor: int, name: str, value: bytes) -> None:
    flags = os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    child = os.open(name, flags, dir_fd=descriptor)
    try:
        view = memoryview(value)
        while view:
            written = os.write(child, view)
            if written <= 0:
                raise SessionContainmentError(
                    f"short write to installer cgroup control {name}"
                )
            view = view[written:]
    finally:
        os.close(child)


@contextmanager
def _runner_journal_locked(
    path: Path,
    uid: int,
    gid: int,
    deadline_monotonic_ns: int,
):
    """Serialize brief runner-journal writes and dead-owner recovery."""

    _verify_dir(path.parent, 0o755, uid, gid)
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags, 0o600)
    locked = False
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != uid
            or info.st_gid != gid
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
        ):
            raise SessionContainmentError(
                "installer runner journal lock has an unsafe identity"
            )
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                break
            except BlockingIOError:
                if time.monotonic_ns() >= deadline_monotonic_ns:
                    raise SessionContainmentError(
                        "installer runner journal lock deadline expired"
                    )
                time.sleep(0.01)
        current = path.lstat()
        if (
            path.is_symlink()
            or (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino)
            or current.st_uid != uid
            or current.st_gid != gid
            or stat.S_IMODE(current.st_mode) != 0o600
            or current.st_nlink != 1
        ):
            raise SessionContainmentError(
                "installer runner journal lock changed while held"
            )
        yield
    finally:
        if locked:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


class _RunnerCgroup:
    """Root-retained exact cgroup for one unprivileged installer runner."""

    def __init__(
        self,
        *,
        record_path: Path,
        record: dict[str, object],
        descriptor: int,
        root_uid: int,
        root_gid: int,
        source_cpu_affinity: tuple[int, ...] | None = None,
        journal_lock_path: Path | None = None,
        journal_deadline_monotonic_ns: int | None = None,
    ) -> None:
        self.record_path = record_path
        self.record = record
        self.descriptor = descriptor
        self.root_uid = root_uid
        self.root_gid = root_gid
        self.source_cpu_affinity = source_cpu_affinity
        self.journal_lock_path = journal_lock_path
        self.journal_deadline_monotonic_ns = journal_deadline_monotonic_ns
        self.scope_removed = False
        self.cleaned = False
        self.runtime_recovery_applied = False

    def _attached_preexec(
        self,
        demote,
        owner_pid: int,
        source_cpu_affinity: tuple[int, ...] | None,
    ):
        descriptor = self.descriptor

        def prepare() -> None:
            try:
                _runner_cgroup_write_at(
                    descriptor,
                    "cgroup.procs",
                    f"{os.getpid()}\n".encode("ascii"),
                )
            finally:
                os.close(descriptor)
            if not source_cpu_affinity:
                os._exit(126)
            try:
                os.sched_setaffinity(0, source_cpu_affinity)
                applied_affinity = set(os.sched_getaffinity(0))
            except OSError:
                os._exit(126)
            if (
                not applied_affinity
                or not applied_affinity <= set(source_cpu_affinity)
            ):
                os._exit(126)
            if demote is not None:
                demote()
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
                os._exit(126)
            if os.getppid() != owner_pid:
                os._exit(126)

        return prepare

    def preexec(self, demote):
        return self._attached_preexec(
            demote,
            int(self.record["owner_pid"]),
            self.source_cpu_affinity,
        )

    def recovery_preexec(self, demote):
        """Attach a retry helper while binding it to the current installer."""

        affinity = self.source_cpu_affinity or tuple(
            sorted(os.sched_getaffinity(0))
        )
        return self._attached_preexec(demote, os.getpid(), affinity)

    def mark_running(self) -> None:
        if self.record.get("phase") != "DELEGATED":
            raise SessionContainmentError(
                "installer runner scope is not ready to enter RUNNING"
            )
        running = dict(self.record)
        running["phase"] = "RUNNING"
        if (
            self.journal_lock_path is None
            or self.journal_deadline_monotonic_ns is None
        ):
            raise SessionContainmentError(
                "installer runner journal authority is absent"
            )
        with _runner_journal_locked(
            self.journal_lock_path,
            self.root_uid,
            self.root_gid,
            self.journal_deadline_monotonic_ns,
        ):
            _atomic_json(
                self.record_path,
                running,
                mode=0o600,
                uid=self.root_uid,
                gid=self.root_gid,
                parent_mode=0o700,
            )
        self.record = running

    def _publish_phase(self, phase: str, *, journal_locked: bool) -> None:
        updated = dict(self.record)
        updated["record_version"] = RUNNER_SCOPE_RECORD_VERSION
        updated["phase"] = phase

        def publish() -> None:
            _atomic_json(
                self.record_path,
                updated,
                mode=0o600,
                uid=self.root_uid,
                gid=self.root_gid,
                parent_mode=0o700,
            )

        if journal_locked:
            publish()
        else:
            if (
                self.journal_lock_path is None
                or self.journal_deadline_monotonic_ns is None
            ):
                raise SessionContainmentError(
                    "installer runner journal authority is absent"
                )
            with _runner_journal_locked(
                self.journal_lock_path,
                self.root_uid,
                self.root_gid,
                self.journal_deadline_monotonic_ns,
            ):
                publish()
        self.record = updated

    def mark_recovered(self, *, journal_locked: bool = False) -> None:
        """Publish successful runtime reconciliation before revocation."""

        phase = self.record.get("phase")
        if phase in {"RECOVERED", "CONTAINED"}:
            return
        if phase not in {"CREATED_ROOT", "DELEGATING", "DELEGATED", "RUNNING"}:
            raise SessionContainmentError(
                "installer runner scope cannot enter RECOVERED"
            )
        self._publish_phase("RECOVERED", journal_locked=journal_locked)

    def mark_contained(self, *, journal_locked: bool = False) -> None:
        """Publish the root-owned, empty, topology-free terminal scope state."""

        phase = self.record.get("phase")
        if phase == "CONTAINED":
            return
        if phase != "RECOVERED":
            raise SessionContainmentError(
                "installer runner scope cannot enter CONTAINED"
            )
        self._publish_phase("CONTAINED", journal_locked=journal_locked)

    def _verify_exact(self) -> Path:
        scope = Path(str(self.record["scope_path"]))
        info = os.fstat(self.descriptor)
        actual_owner = (info.st_uid, info.st_gid)
        allowed_owners = {
            (self.root_uid, self.root_gid),
            (
                int(self.record["target_uid"]),
                int(self.record["target_gid"]),
            ),
        }
        if (
            not stat.S_ISDIR(info.st_mode)
            or (info.st_dev, info.st_ino)
            != (self.record["scope_device"], self.record["scope_inode"])
            or actual_owner not in allowed_owners
        ):
            raise SessionContainmentError("installer runner cgroup handle changed")
        named = scope.lstat()
        if (
            scope.is_symlink()
            or not stat.S_ISDIR(named.st_mode)
            or (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino)
            or (named.st_uid, named.st_gid) != actual_owner
        ):
            raise SessionContainmentError("installer runner cgroup path changed")
        return scope

    def _remove_nested(self, deadline_monotonic_ns: int) -> None:
        seen = [0]

        def remove_from(descriptor: int, depth: int) -> None:
            if time.monotonic_ns() >= deadline_monotonic_ns:
                raise SessionContainmentError(
                    "installer runner cgroup cleanup deadline expired"
                )
            if depth > RUNNER_CGROUP_CLEANUP_MAX_DEPTH:
                raise SessionContainmentError(
                    "installer runner nested cgroup depth exceeded"
                )
            truncated = False
            with os.scandir(descriptor) as entries:
                for entry in entries:
                    if entry.is_symlink():
                        raise SessionContainmentError(
                            "installer runner cgroup contains a symlink"
                        )
                    if entry.is_dir(follow_symlinks=False):
                        if seen[0] >= MAX_SWITCH_INVENTORY_ENTRIES:
                            truncated = True
                            break
                        seen[0] += 1
                        name = entry.name
                        if time.monotonic_ns() >= deadline_monotonic_ns:
                            raise SessionContainmentError(
                                "installer runner cgroup cleanup deadline expired"
                            )
                        flags = (
                            os.O_RDONLY
                            | getattr(os, "O_DIRECTORY", 0)
                            | getattr(os, "O_CLOEXEC", 0)
                            | getattr(os, "O_NOFOLLOW", 0)
                        )
                        child = os.open(name, flags, dir_fd=descriptor)
                        try:
                            before = os.fstat(child)
                            if (
                                not stat.S_ISDIR(before.st_mode)
                                or before.st_dev != self.record["scope_device"]
                            ):
                                raise SessionContainmentError(
                                    "installer runner nested cgroup has an unsafe identity"
                                )
                            remove_from(child, depth + 1)
                            after = os.stat(
                                name,
                                dir_fd=descriptor,
                                follow_symlinks=False,
                            )
                            if (after.st_dev, after.st_ino) != (
                                before.st_dev,
                                before.st_ino,
                            ):
                                raise SessionContainmentError(
                                    "installer runner nested cgroup changed before removal"
                                )
                        finally:
                            os.close(child)
                        try:
                            os.rmdir(name, dir_fd=descriptor)
                        except OSError as exc:
                            raise SessionContainmentError(
                                "installer runner nested cgroup could not be removed"
                            ) from exc
            if truncated:
                # The entries already visited were removed before failing
                # closed.  A subsequent journal recovery can therefore make
                # bounded progress through an over-broad legacy hierarchy.
                raise SessionContainmentError(
                    "installer runner nested cgroup limit exceeded"
                )

        remove_from(self.descriptor, 0)

    def cleanup(
        self,
        deadline_monotonic_ns: int,
        *,
        after_kill: Callable[[], bool] | None = None,
        journal_locked: bool = False,
    ) -> None:
        if self.scope_removed:
            return
        scope = self._verify_exact()
        try:
            # Kill first but preserve the delegated topology.  Qualification
            # recovery may need the still-named parent and nested scope inodes
            # to reconcile its user-owned durable records before root removes
            # the enclosing accounting scope.
            _runner_cgroup_write_at(self.descriptor, "cgroup.kill", b"1\n")
            while True:
                if time.monotonic_ns() >= deadline_monotonic_ns:
                    raise SessionContainmentError(
                        "installer runner cgroup remained populated"
                    )
                try:
                    events = dict(
                        line.split(" ", 1)
                        for line in _runner_cgroup_read_at(
                            self.descriptor, "cgroup.events", 4096
                        ).decode("ascii").splitlines()
                    )
                except (UnicodeError, ValueError) as exc:
                    raise SessionContainmentError(
                        "installer runner cgroup events are invalid"
                    ) from exc
                if events.get("populated") == "0":
                    break
                if events.get("populated") != "1":
                    raise SessionContainmentError(
                        "installer runner cgroup populated state is invalid"
                    )
                time.sleep(0.01)
            if after_kill is not None:
                applied = after_kill()
                if type(applied) is not bool:
                    raise SessionContainmentError(
                        "installer runner recovery returned an invalid outcome"
                    )
                self.runtime_recovery_applied = (
                    self.runtime_recovery_applied or applied
                )
            # The release/rung gate plus installer operation locks prevent a
            # second legitimate wrapper from entering this delegated scope.
            # This intermediate witness lets crash replay skip user recovery
            # after any partial root-ownership revocation, when a demoted
            # helper could no longer use the current cgroup as its parent.
            self.mark_recovered(journal_locked=journal_locked)

            # Only a successful recovery callback permits delegation
            # revocation and recursive removal.  If it fails, the empty named
            # hierarchy and root journal remain intact for an exact retry.
            scope = self._verify_exact()
            os.chown(
                scope,
                self.root_uid,
                self.root_gid,
                follow_symlinks=False,
            )
            for control in (
                "cgroup.procs",
                "cgroup.threads",
                "cgroup.subtree_control",
            ):
                try:
                    os.chown(
                        scope / control,
                        self.root_uid,
                        self.root_gid,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    if control != "cgroup.threads":
                        raise
            # Close the cooperative callback/revocation window before any
            # recursive removal.
            _runner_cgroup_write_at(self.descriptor, "cgroup.kill", b"1\n")
            while True:
                if time.monotonic_ns() >= deadline_monotonic_ns:
                    raise SessionContainmentError(
                        "installer runner cgroup remained populated after recovery"
                    )
                try:
                    events = dict(
                        line.split(" ", 1)
                        for line in _runner_cgroup_read_at(
                            self.descriptor, "cgroup.events", 4096
                        ).decode("ascii").splitlines()
                    )
                except (UnicodeError, ValueError) as exc:
                    raise SessionContainmentError(
                        "installer runner cgroup events are invalid after recovery"
                    ) from exc
                if events.get("populated") == "0":
                    break
                if events.get("populated") != "1":
                    raise SessionContainmentError(
                        "installer runner cgroup populated state is invalid after recovery"
                    )
                time.sleep(0.01)
            self._remove_nested(deadline_monotonic_ns)
            info = os.fstat(self.descriptor)
            named = scope.lstat()
            if (
                (info.st_dev, info.st_ino)
                != (self.record["scope_device"], self.record["scope_inode"])
                or (named.st_dev, named.st_ino)
                != (info.st_dev, info.st_ino)
                or (info.st_uid, info.st_gid)
                != (self.root_uid, self.root_gid)
            ):
                raise SessionContainmentError(
                    "installer runner cgroup changed after delegation revocation"
                )
            # CONTAINED is the only missing-scope state that proves user
            # delegation was revoked, both kill barriers completed, and all
            # nested topology was removed.  Publish it while the exact empty
            # parent is still named, then rmdir.
            self.mark_contained(journal_locked=journal_locked)
            scope.rmdir()
            try:
                scope.lstat()
            except FileNotFoundError:
                pass
            else:
                raise SessionContainmentError(
                    "installer runner cgroup remained after rmdir"
                )
            self.scope_removed = True
        finally:
            if self.scope_removed and self.descriptor >= 0:
                os.close(self.descriptor)
                self.descriptor = -1

    def finalize_record(self, *, journal_locked: bool = False) -> None:
        """Delete durable authority only after scope removal and leader reap."""

        if self.cleaned:
            return
        if not self.scope_removed:
            raise SessionContainmentError(
                "installer runner record cannot finalize before containment"
            )
        def finalize() -> None:
            raw, _mode = _read_regular(
                self.record_path,
                uid=self.root_uid,
                gid=self.root_gid,
                mode=0o600,
                maximum=16_384,
            )
            if raw != _canonical_json(self.record) + b"\n":
                raise SessionContainmentError(
                    "installer runner scope record changed before deletion"
                )
            self.record_path.unlink()
            _fsync_dir(self.record_path.parent)
            self.cleaned = True

        if journal_locked:
            finalize()
            return
        if (
            self.journal_lock_path is None
            or self.journal_deadline_monotonic_ns is None
        ):
            raise SessionContainmentError(
                "installer runner journal authority is absent"
            )
        with _runner_journal_locked(
            self.journal_lock_path,
            self.root_uid,
            self.root_gid,
            self.journal_deadline_monotonic_ns,
        ):
            finalize()

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


def _route_profile_matches_rung(route_profile: object, rung: object) -> bool:
    """Return whether one closed route profile may authorize ``rung``."""

    if type(route_profile) is not str or ROUTE_PROFILE_RE.fullmatch(route_profile) is None:
        return False
    if type(rung) is not str or RUNG_TOKEN_RE.fullmatch(rung) is None:
        return False
    if route_profile == "auto":
        return True
    if route_profile == "auto-no-direct":
        return rung != "direct"
    return route_profile == rung


class FileRecord(NamedTuple):
    path: str
    sha256: str
    size: int
    mode: int


class ReleasePlan(NamedTuple):
    release_id: str
    files: tuple[FileRecord, ...]
    root_files: tuple[tuple[str, str], ...]
    identity: dict[str, object]


class InstallResult(NamedTuple):
    release_id: str
    changed: bool
    operation: str


class SmokeResult(NamedTuple):
    returncode: int
    stdout: bytes
    stderr: bytes
    duration_ms: int


class CanaryExecResult(NamedTuple):
    release_id: str
    rung: str
    returncode: int
    run_id: str
    transcript_sha256: str


class QualificationExecResult(NamedTuple):
    release_id: str
    step: str
    status: str
    returncode: int
    result_sha256: str
    error_code: str | None
    error_sha256: str | None


def _canonical_absolute(
    value: Path,
    label: str,
    *,
    reject_root: bool = False,
) -> Path:
    """Reject lexical escapes and existing symlink components before effects."""

    candidate = Path(value)
    if not candidate.is_absolute():
        raise ReleaseError(f"{label} must be absolute")
    try:
        resolved = candidate.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise ReleaseError(f"cannot canonicalize {label}: {candidate}: {exc}") from exc
    if resolved != candidate:
        raise ReleaseError(
            f"{label} must be canonical and contain no symlink ambiguity: {candidate}"
        )
    if reject_root and candidate == Path("/"):
        raise ReleaseError(f"{label} must not be /")
    return candidate


class Layout:
    """Every path and ownership identity used by an install."""

    def __init__(
        self,
        *,
        source_dir: Path,
        user_root: Path,
        root_root: Path,
        state_root: Path,
        entrypoint: Path,
        root_state_root: Path | None = None,
        broker_state_root: Path | None = None,
        target_uid: int | None = None,
        target_gid: int | None = None,
        root_uid: int | None = None,
        root_gid: int | None = None,
        test_install: bool = False,
        test_runner_scopes: bool = False,
        openvpn_binary: Path = Path("/usr/sbin/openvpn"),
    ) -> None:
        self.source_dir = Path(source_dir)
        self.user_root = Path(user_root)
        self.root_root = Path(root_root)
        self.state_root = Path(state_root)
        self.entrypoint = Path(entrypoint)
        self._root_control = (
            self.root_root / "control"
            if root_state_root is None
            else Path(root_state_root)
        )
        self._broker_state = (
            self.root_root / "broker-state"
            if broker_state_root is None
            else Path(broker_state_root)
        )
        self.target_uid = os.geteuid() if target_uid is None else target_uid
        self.target_gid = os.getegid() if target_gid is None else target_gid
        self.root_uid = os.geteuid() if root_uid is None else root_uid
        self.root_gid = os.getegid() if root_gid is None else root_gid
        self.test_install = bool(test_install)
        if test_runner_scopes and not self.test_install:
            raise ReleaseError(
                "runner-scope test seam requires an explicit test install"
            )
        self.test_runner_scopes = bool(test_runner_scopes)
        self.openvpn_binary = Path(openvpn_binary)

    @property
    def user_releases(self) -> Path:
        return self.user_root / "releases"

    @property
    def root_releases(self) -> Path:
        return self.root_root / "releases"

    @property
    def current(self) -> Path:
        return self.user_root / "current"

    @property
    def root_current(self) -> Path:
        return self.root_root / "current"

    @property
    def selected(self) -> Path:
        return self.state_root / "selected-release.json"

    @property
    def root_control(self) -> Path:
        return self._root_control

    @property
    def root_selected(self) -> Path:
        return self.root_control / "selected-release.json"

    @property
    def rollback_deny(self) -> Path:
        return self.root_control / "rollback-deny.json"

    @property
    def install_lock(self) -> Path:
        return self.root_control / "install.lock"

    @property
    def operation_lock(self) -> Path:
        return self.root_control / "operation.lock"

    @property
    def canary_auth(self) -> Path:
        return self.root_control / "canary-auth.lock"

    @property
    def runner_scope_root(self) -> Path:
        return self.root_control / "runner-scopes"

    @property
    def runner_scope_lock(self) -> Path:
        return self.root_control / "runner-scopes.lock"

    @property
    def evidence_root(self) -> Path:
        return self.root_control / "evidence"

    def evidence_path(self, release_id: str) -> Path:
        if RELEASE_ID_RE.fullmatch(release_id) is None:
            raise ReleaseError(f"invalid evidence release ID: {release_id!r}")
        return self.evidence_root / f"{release_id}.json"

    @property
    def rung_evidence_root(self) -> Path:
        return self.root_control / "rung-evidence"

    def rung_evidence_path(self, release_id: str, digest: str) -> Path:
        if RELEASE_ID_RE.fullmatch(release_id) is None:
            raise ReleaseError(f"invalid rung evidence release ID: {release_id!r}")
        if RELEASE_ID_RE.fullmatch(digest) is None:
            raise ReleaseError(f"invalid rung evidence digest: {digest!r}")
        return self.rung_evidence_root / release_id / f"{digest}.json"

    @property
    def rung_transcript_root(self) -> Path:
        return self.root_control / "rung-transcripts"

    def rung_transcript_dir(self, release_id: str, nonce: str) -> Path:
        if RELEASE_ID_RE.fullmatch(release_id) is None:
            raise ReleaseError(f"invalid transcript release ID: {release_id!r}")
        if RELEASE_ID_RE.fullmatch(nonce) is None:
            raise ReleaseError(f"invalid canary nonce: {nonce!r}")
        return self.rung_transcript_root / release_id / nonce

    @property
    def rung_canary(self) -> Path:
        return self.root_control / "rung-canary.json"

    @property
    def canary_terminal(self) -> Path:
        return self.root_control / "canary-terminal.json"

    @property
    def qualification_root(self) -> Path:
        return self.root_control / "qualification"

    def qualification_release_dir(self, release_id: str) -> Path:
        if RELEASE_ID_RE.fullmatch(release_id) is None:
            raise ReleaseError(f"invalid qualification release ID: {release_id!r}")
        return self.qualification_root / release_id

    def qualification_result_path(self, release_id: str, step: str) -> Path:
        if step not in QUALIFICATION_STEPS:
            raise ReleaseError(f"invalid release qualification step: {step!r}")
        return self.qualification_release_dir(release_id) / f"{step}.json"

    def qualification_state_path(self, release_id: str) -> Path:
        return self.qualification_release_dir(release_id) / "release.json"

    def rung_qualification_path(self, release_id: str, nonce: str) -> Path:
        return self.rung_transcript_dir(release_id, nonce) / "real-pair.json"

    @property
    def boot_inventory_root(self) -> Path:
        return self.root_control / "boot-inventory"

    def boot_inventory_path(self, release_id: str) -> Path:
        if RELEASE_ID_RE.fullmatch(release_id) is None:
            raise ReleaseError(f"invalid boot inventory release ID: {release_id!r}")
        return self.boot_inventory_root / f"{release_id}.json"

    @property
    def broker_state(self) -> Path:
        return self._broker_state

    @property
    def broker_ledger(self) -> Path:
        return self.broker_state / "ledger.json"

    @property
    def broker_lock(self) -> Path:
        return self.broker_state / "broker.lock"

    @property
    def multi_control(self) -> Path:
        return self.state_root.parent / "control"

    @property
    def recovery_fence(self) -> Path:
        return self.multi_control / "recovery.fence"

    @property
    def supervisor_socket(self) -> Path:
        return self.multi_control / "supervisor.sock"

    @property
    def supervisor_ready(self) -> Path:
        return self.multi_control / "supervisor.ready"

    @property
    def provider_root(self) -> Path:
        return self.multi_control / "p"

    @property
    def qualify_root(self) -> Path:
        return self.multi_control / "qualify"

    @property
    def recovery_record_roots(self) -> tuple[Path, ...]:
        recovery = self.multi_control / "recovery"
        return (
            recovery / "providers",
            recovery / "children",
            recovery / "probes",
            recovery / "provider-scopes",
            recovery / "detached-scopes",
        )

    @property
    def intent_root(self) -> Path:
        return self.multi_control / "intents"

    @property
    def leader_root(self) -> Path:
        return self.multi_control / "leaders"

    @property
    def broker_entrypoint(self) -> Path:
        return self.root_root / "vpn-broker"

    @classmethod
    def defaults(
        cls,
        source_dir: Path,
        *,
        prefix: Path | None = None,
        home: Path | None = None,
        test_openvpn_binary: Path | None = None,
    ) -> "Layout":
        euid = os.geteuid()
        egid = os.getegid()
        if prefix is not None:
            prefix = _canonical_absolute(
                Path(prefix), "test prefix", reject_root=True
            )
            target_uid = root_uid = euid
            target_gid = root_gid = egid
            real_home = Path.home() if home is None else Path(home)
        elif euid == 0 and os.environ.get("SUDO_UID"):
            try:
                target_uid = int(os.environ["SUDO_UID"])
            except ValueError as exc:
                raise ReleaseError("SUDO_UID is not numeric") from exc
            if target_uid < 0:
                raise ReleaseError("SUDO_UID is negative")
            try:
                account = pwd.getpwuid(target_uid)
            except KeyError as exc:
                raise ReleaseError(f"calling sudo UID {target_uid} has no passwd entry") from exc
            target_gid = account.pw_gid
            account_home = Path(account.pw_dir)
            if home is not None and Path(home).absolute() != account_home.absolute():
                raise ReleaseError("live --home must match the calling sudo user's passwd home")
            real_home = account_home
            root_uid = root_gid = 0
        else:
            target_uid = euid
            target_gid = egid
            real_home = Path.home() if home is None else Path(home)
            root_uid = root_gid = 0

        real_home = _canonical_absolute(real_home, "home", reject_root=True)

        def rebased(path: Path) -> Path:
            if prefix is None:
                return path
            if not path.is_absolute():
                raise ReleaseError(f"cannot prefix relative default path: {path}")
            candidate = prefix / path.relative_to(path.anchor)
            try:
                resolved = candidate.resolve(strict=False)
                resolved.relative_to(prefix)
            except (OSError, RuntimeError, ValueError) as exc:
                raise ReleaseError(
                    f"prefixed layout path escapes its canonical prefix: {candidate}"
                ) from exc
            if resolved != candidate or resolved == prefix:
                raise ReleaseError(
                    f"prefixed layout path is not canonical and contained: {candidate}"
                )
            return candidate

        return cls(
            source_dir=Path(source_dir),
            user_root=rebased(real_home / ".local/lib/grok-proxy"),
            root_root=rebased(Path("/usr/local/libexec/grok-proxy")),
            root_state_root=rebased(Path("/var/lib/grok-proxy/release-control")),
            broker_state_root=rebased(Path("/var/lib/grok-proxy/broker")),
            state_root=rebased(real_home / ".local/state/grok-proxy/release-control"),
            entrypoint=rebased(real_home / ".local/bin/grok-remote"),
            target_uid=target_uid,
            target_gid=target_gid,
            root_uid=root_uid,
            root_gid=root_gid,
            test_install=prefix is not None,
            openvpn_binary=(
                Path("/usr/sbin/openvpn")
                if test_openvpn_binary is None
                else Path(test_openvpn_binary)
            ),
        )


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _production_direct_admission_is_exact(
    contents: Mapping[str, bytes],
) -> bool:
    """Return whether production entrypoints match the reviewed admission set."""

    return (
        set(contents) == set(DIRECT_ADMISSION_PRODUCTION_PATHS)
        and tuple(
            _sha256_bytes(contents[relative])
            for relative in DIRECT_ADMISSION_PRODUCTION_PATHS
        )
        in DIRECT_ADMISSION_PRODUCTION_BUNDLES
    )


def _bounded_output_diagnostic(stdout: bytes, stderr: bytes) -> str:
    """Describe child output without rendering attacker-controlled bytes."""
    return (
        f"stdout_bytes={len(stdout)} stdout_sha256={_sha256_bytes(stdout)} "
        f"stderr_bytes={len(stderr)} stderr_sha256={_sha256_bytes(stderr)}"
    )


_DIRECTORY_OPEN_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)


def _open_directory_path(path: Path) -> int:
    """Open an absolute directory path without following any component link."""

    path = Path(path).absolute()
    if not path.is_absolute():
        raise ReleaseError(f"directory path is not absolute: {path}")
    try:
        descriptor = os.open(path.anchor or "/", _DIRECTORY_OPEN_FLAGS)
    except OSError as exc:
        raise ReleaseError(f"cannot open directory root for {path}: {exc}") from exc
    current = Path(path.anchor or "/")
    try:
        for name in path.parts[1:]:
            current = current / name
            try:
                child = os.open(name, _DIRECTORY_OPEN_FLAGS, dir_fd=descriptor)
            except OSError as exc:
                raise ReleaseError(
                    f"cannot open directory component safely {current}: {exc}"
                ) from exc
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _directory_path_matches(path: Path, info: os.stat_result) -> bool:
    """Return whether the current no-link path still names ``info``."""

    try:
        descriptor = _open_directory_path(path)
    except ReleaseError:
        return False
    try:
        current = os.fstat(descriptor)
        return (current.st_dev, current.st_ino) == (info.st_dev, info.st_ino)
    finally:
        os.close(descriptor)


def _open_verified_directory(path: Path, mode: int, uid: int, gid: int) -> int:
    """Open and retain one exact directory after checking its security state."""

    descriptor = _open_directory_path(path)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode):
            raise ReleaseError(f"expected safe directory: {path}")
        _check_owner(info, uid, gid, path)
        actual_mode = stat.S_IMODE(info.st_mode)
        if actual_mode != mode:
            raise ReleaseError(
                f"unexpected mode for {path}: {actual_mode:04o}; expected {mode:04o}"
            )
        if not _directory_path_matches(path, info):
            raise ReleaseError(f"directory path changed while opening: {path}")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _assert_directory_path_identity(path: Path, descriptor: int) -> None:
    info = os.fstat(descriptor)
    if not stat.S_ISDIR(info.st_mode) or not _directory_path_matches(path, info):
        raise ReleaseError(f"directory path changed during operation: {path}")


def _fsync_dir(path: Path) -> None:
    try:
        fd = _open_directory_path(path)
    except ReleaseError as exc:
        raise ReleaseError(f"cannot open directory for fsync {path}: {exc}") from exc
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _lstat(path: Path) -> os.stat_result | None:
    try:
        return path.lstat()
    except FileNotFoundError:
        return None


def _present(path: Path) -> bool:
    return _lstat(path) is not None


def _check_owner(info: os.stat_result, uid: int, gid: int, path: Path) -> None:
    if info.st_uid != uid or info.st_gid != gid:
        raise ReleaseError(
            f"unexpected owner for {path}: {info.st_uid}:{info.st_gid}; expected {uid}:{gid}"
        )


def _verify_dir(path: Path, mode: int, uid: int, gid: int) -> None:
    descriptor = _open_verified_directory(path, mode, uid, gid)
    os.close(descriptor)


def _verify_release_dir(path: Path, uid: int, gid: int) -> int:
    """Verify one immutable release root and return its access state."""

    descriptor = _open_directory_path(path)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode):
            raise ReleaseError(f"expected safe release directory: {path}")
        _check_owner(info, uid, gid, path)
        actual_mode = stat.S_IMODE(info.st_mode)
        if actual_mode not in {ACTIVE_RELEASE_MODE, ARCHIVED_RELEASE_MODE}:
            raise ReleaseError(
                f"unexpected release access mode for {path}: {actual_mode:04o}"
            )
        if not _directory_path_matches(path, info):
            raise ReleaseError(f"release directory path changed: {path}")
        return actual_mode
    finally:
        os.close(descriptor)


def _ensure_dir(path: Path, mode: int, uid: int, gid: int) -> None:
    """Create and converge a directory through retained, no-link descriptors."""

    path = path.absolute()
    if path == Path(path.anchor or "/"):
        raise ReleaseError("refusing to manage the filesystem root")
    current = Path(path.anchor or "/")
    try:
        descriptor = os.open(current, _DIRECTORY_OPEN_FLAGS)
    except OSError as exc:
        raise ReleaseError(f"cannot open directory root for {path}: {exc}") from exc
    managed = False
    while True:
        try:
            for name in path.parts[1:]:
                current = current / name
                try:
                    child = os.open(name, _DIRECTORY_OPEN_FLAGS, dir_fd=descriptor)
                except FileNotFoundError:
                    managed = True
                    try:
                        os.mkdir(name, 0o700, dir_fd=descriptor)
                    except FileExistsError:
                        # Another installer or the target user can win creation.
                        # The object is accepted only after a no-link open and an
                        # ownership check, and all metadata changes stay on that
                        # retained descriptor.
                        pass
                    except OSError as exc:
                        raise ReleaseError(
                            f"cannot create directory {current}: {exc}"
                        ) from exc
                    try:
                        child = os.open(
                            name, _DIRECTORY_OPEN_FLAGS, dir_fd=descriptor
                        )
                    except OSError as exc:
                        raise ReleaseError(
                            f"cannot open created directory safely {current}: {exc}"
                        ) from exc
                except OSError as exc:
                    raise ReleaseError(
                        f"unsafe path component {current}: {exc}"
                    ) from exc

                try:
                    info = os.fstat(child)
                    if not stat.S_ISDIR(info.st_mode):
                        raise ReleaseError(f"unsafe path component: {current}")
                    if managed:
                        if info.st_uid not in {uid, os.geteuid()}:
                            raise ReleaseError(
                                f"unsafe concurrently-created directory: {current}"
                            )
                        os.fchown(child, uid, gid)
                        os.fchmod(child, mode if current == path else 0o755)
                        os.fsync(child)
                        os.fsync(descriptor)
                except BaseException:
                    os.close(child)
                    raise
                os.close(descriptor)
                descriptor = child

            info = os.fstat(descriptor)
            _check_owner(info, uid, gid, path)
            os.fchmod(descriptor, mode)
            os.fsync(descriptor)
            final = os.fstat(descriptor)
            _check_owner(final, uid, gid, path)
            if stat.S_IMODE(final.st_mode) != mode:
                raise ReleaseError(f"directory mode did not converge: {path}")
            _assert_directory_path_identity(path, descriptor)
        finally:
            os.close(descriptor)
        return


def _read_regular(
    path: Path,
    *,
    uid: int | None = None,
    gid: int | None = None,
    mode: int | None = None,
    maximum: int | None = None,
) -> tuple[bytes, int]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    parent = _open_directory_path(path.parent)
    try:
        fd = os.open(path.name, flags, dir_fd=parent)
    except OSError as exc:
        os.close(parent)
        raise ReleaseError(f"cannot open regular file safely {path}: {exc}") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ReleaseError(f"not a regular file: {path}")
        if uid is not None and gid is not None:
            _check_owner(info, uid, gid, path)
        actual_mode = stat.S_IMODE(info.st_mode)
        if mode is not None and actual_mode != mode:
            raise ReleaseError(
                f"unexpected mode for {path}: {actual_mode:04o}; expected {mode:04o}"
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if maximum is not None and total > maximum:
                raise ReleaseError(f"file exceeds size limit: {path}")
            chunks.append(chunk)
        return b"".join(chunks), actual_mode
    finally:
        os.close(fd)
        os.close(parent)


def _write_all(fd: int, data: bytes, destination: Path) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise ReleaseError(f"short write while creating {destination}")
        view = view[written:]


def _safe_relpath(value: str) -> str:
    candidate = PurePosixPath(value)
    if candidate.is_absolute() or not candidate.parts:
        raise ReleaseError(f"runtime path must be relative: {value!r}")
    if any(part in ("", ".", "..") for part in candidate.parts):
        raise ReleaseError(f"unsafe runtime path: {value!r}")
    return candidate.as_posix()


def _atomic_write(
    path: Path,
    data: bytes,
    *,
    mode: int,
    uid: int,
    gid: int,
    parent_mode: int,
    parent_uid: int | None = None,
    parent_gid: int | None = None,
    replace_owners: frozenset[tuple[int, int]] | None = None,
    allow_selector_replacement: bool = False,
) -> None:
    expected_parent_uid = uid if parent_uid is None else parent_uid
    expected_parent_gid = gid if parent_gid is None else parent_gid
    directory = _open_verified_directory(
        path.parent,
        parent_mode,
        expected_parent_uid,
        expected_parent_gid,
    )
    try:
        try:
            existing = os.stat(
                path.name, dir_fd=directory, follow_symlinks=False
            )
        except FileNotFoundError:
            existing = None
        if existing is not None:
            allowed = stat.S_ISREG(existing.st_mode) or (
                allow_selector_replacement and stat.S_ISLNK(existing.st_mode)
            )
            if not allowed:
                raise ReleaseError(f"refusing to replace unsafe object: {path}")
            allowed_owners = replace_owners or frozenset({(uid, gid)})
            if (existing.st_uid, existing.st_gid) not in allowed_owners:
                raise ReleaseError(
                    f"unexpected owner for {path}: {existing.st_uid}:{existing.st_gid}; "
                    f"expected one of {sorted(allowed_owners)}"
                )
        temporary = f".{path.name}.tmp-{uuid.uuid4().hex}"
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        fd = os.open(temporary, flags, 0o600, dir_fd=directory)
        try:
            os.fchown(fd, uid, gid)
            os.fchmod(fd, mode)
            _write_all(fd, data, path)
            os.fsync(fd)
            written = os.fstat(fd)
        except BaseException:
            try:
                named = os.stat(
                    temporary, dir_fd=directory, follow_symlinks=False
                )
                opened = os.fstat(fd)
                if (named.st_dev, named.st_ino) == (opened.st_dev, opened.st_ino):
                    os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
            raise
        finally:
            os.close(fd)
        try:
            os.replace(
                temporary,
                path.name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
            )
            published = os.stat(
                path.name, dir_fd=directory, follow_symlinks=False
            )
            if (
                not stat.S_ISREG(published.st_mode)
                or (published.st_dev, published.st_ino)
                != (written.st_dev, written.st_ino)
                or (published.st_uid, published.st_gid) != (uid, gid)
                or stat.S_IMODE(published.st_mode) != mode
            ):
                raise ReleaseError(f"atomic publication changed identity: {path}")
            os.fsync(directory)
            _assert_directory_path_identity(path.parent, directory)
        except BaseException:
            try:
                named = os.stat(
                    temporary, dir_fd=directory, follow_symlinks=False
                )
                if (named.st_dev, named.st_ino) == (written.st_dev, written.st_ino):
                    os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
            raise
    finally:
        os.close(directory)


def _atomic_json(
    path: Path,
    value: object,
    *,
    mode: int,
    uid: int,
    gid: int,
    parent_mode: int,
) -> bytes:
    data = _canonical_json(value) + b"\n"
    _atomic_write(
        path, data, mode=mode, uid=uid, gid=gid, parent_mode=parent_mode
    )
    return data


def _exclusive_write(
    path: Path,
    data: bytes,
    *,
    mode: int,
    uid: int,
    gid: int,
    parent_mode: int,
) -> None:
    """Durably create one immutable record without a replacement window."""

    directory = _open_verified_directory(path.parent, parent_mode, uid, gid)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path.name, flags, 0o600, dir_fd=directory)
    except OSError as exc:
        os.close(directory)
        raise ReleaseError(f"cannot exclusively create {path}: {exc}") from exc
    try:
        os.fchown(descriptor, uid, gid)
        os.fchmod(descriptor, mode)
        _write_all(descriptor, data, path)
        os.fsync(descriptor)
        opened = os.fstat(descriptor)
        named = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        if (
            not stat.S_ISREG(named.st_mode)
            or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)
            or (named.st_uid, named.st_gid) != (uid, gid)
            or stat.S_IMODE(named.st_mode) != mode
        ):
            raise ReleaseError(f"exclusive publication changed identity: {path}")
        os.fsync(directory)
        _assert_directory_path_identity(path.parent, directory)
    except BaseException:
        try:
            named = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
            opened = os.fstat(descriptor)
            if (named.st_dev, named.st_ino) == (opened.st_dev, opened.st_ino):
                os.unlink(path.name, dir_fd=directory)
                os.fsync(directory)
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(descriptor)
        os.close(directory)


def _exclusive_json(
    path: Path,
    value: object,
    *,
    mode: int,
    uid: int,
    gid: int,
    parent_mode: int,
) -> bytes:
    data = _canonical_json(value) + b"\n"
    _exclusive_write(
        path,
        data,
        mode=mode,
        uid=uid,
        gid=gid,
        parent_mode=parent_mode,
    )
    return data


def _exclusive_runner_record(
    path: Path,
    value: object,
    *,
    uid: int,
    gid: int,
) -> None:
    """Publish a complete initial runner record without a partial final path."""

    data = _canonical_json(value) + b"\n"
    temporary = f".{path.name}.tmp-{uuid.uuid4().hex}"
    directory = _open_verified_directory(path.parent, 0o700, uid, gid)
    descriptor = -1
    try:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(temporary, flags, 0o600, dir_fd=directory)
        os.fchown(descriptor, uid, gid)
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, data, path)
        os.fsync(descriptor)
        staged = os.fstat(descriptor)
        os.close(descriptor)
        descriptor = -1
        try:
            os.link(
                temporary,
                path.name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
                follow_symlinks=False,
            )
        except FileExistsError as exc:
            raise ReleaseError(
                f"runner scope record already exists: {path}"
            ) from exc
        os.fsync(directory)
        published = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        if (
            not stat.S_ISREG(published.st_mode)
            or (published.st_dev, published.st_ino)
            != (staged.st_dev, staged.st_ino)
            or (published.st_uid, published.st_gid) != (uid, gid)
            or stat.S_IMODE(published.st_mode) != 0o600
        ):
            raise ReleaseError(f"runner scope record changed identity: {path}")
        os.unlink(temporary, dir_fd=directory)
        os.fsync(directory)
        _assert_directory_path_identity(path.parent, directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass
        os.close(directory)


def _atomic_symlink(
    path: Path,
    target: str,
    *,
    uid: int,
    gid: int,
    parent_mode: int,
    parent_uid: int | None = None,
    parent_gid: int | None = None,
) -> None:
    expected_parent_uid = uid if parent_uid is None else parent_uid
    expected_parent_gid = gid if parent_gid is None else parent_gid
    directory = _open_verified_directory(
        path.parent,
        parent_mode,
        expected_parent_uid,
        expected_parent_gid,
    )
    try:
        try:
            existing = os.stat(
                path.name, dir_fd=directory, follow_symlinks=False
            )
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if not stat.S_ISLNK(existing.st_mode):
                raise ReleaseError(f"refusing to replace non-symlink selector: {path}")
            _check_owner(existing, uid, gid, path)
        temporary = f".{path.name}.tmp-{uuid.uuid4().hex}"
        os.symlink(target, temporary, dir_fd=directory)
        try:
            os.chown(
                temporary,
                uid,
                gid,
                dir_fd=directory,
                follow_symlinks=False,
            )
            staged = os.stat(
                temporary, dir_fd=directory, follow_symlinks=False
            )
            os.replace(
                temporary,
                path.name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
            )
            published = os.stat(
                path.name, dir_fd=directory, follow_symlinks=False
            )
            if (
                not stat.S_ISLNK(published.st_mode)
                or (published.st_dev, published.st_ino)
                != (staged.st_dev, staged.st_ino)
                or (published.st_uid, published.st_gid) != (uid, gid)
                or os.readlink(path.name, dir_fd=directory) != target
            ):
                raise ReleaseError(f"selector publication changed identity: {path}")
            os.fsync(directory)
            _assert_directory_path_identity(path.parent, directory)
        except BaseException:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
            raise
    finally:
        os.close(directory)


def _remove_tree_at(
    parent: int,
    name: str,
    *,
    uid: int,
    gid: int,
    display: Path,
) -> None:
    """Remove one owned staging tree without leaving ``parent``."""

    try:
        descriptor = os.open(name, _DIRECTORY_OPEN_FLAGS, dir_fd=parent)
    except OSError as exc:
        raise ReleaseError(f"cannot open staging tree safely {display}: {exc}") from exc

    def clear(directory: int, shown: Path) -> None:
        info = os.fstat(directory)
        if not stat.S_ISDIR(info.st_mode):
            raise ReleaseError(f"staging object is not a directory: {shown}")
        _check_owner(info, uid, gid, shown)
        os.fchmod(directory, 0o700)
        with os.scandir(directory) as entries:
            names = sorted(entry.name for entry in entries)
        for child_name in names:
            child_path = shown / child_name
            child_info = os.stat(
                child_name, dir_fd=directory, follow_symlinks=False
            )
            _check_owner(child_info, uid, gid, child_path)
            if stat.S_ISDIR(child_info.st_mode):
                child = os.open(
                    child_name, _DIRECTORY_OPEN_FLAGS, dir_fd=directory
                )
                try:
                    opened = os.fstat(child)
                    if (opened.st_dev, opened.st_ino) != (
                        child_info.st_dev,
                        child_info.st_ino,
                    ):
                        raise ReleaseError(
                            f"staging directory changed identity: {child_path}"
                        )
                    clear(child, child_path)
                finally:
                    os.close(child)
                os.rmdir(child_name, dir_fd=directory)
            elif stat.S_ISREG(child_info.st_mode):
                os.unlink(child_name, dir_fd=directory)
            else:
                raise ReleaseError(
                    f"refusing to remove staging tree containing link: {child_path}"
                )
        os.fsync(directory)

    try:
        clear(descriptor, display)
    finally:
        os.close(descriptor)
    os.rmdir(name, dir_fd=parent)
    os.fsync(parent)


def _freeze_tree_at(descriptor: int, *, uid: int, gid: int, display: Path) -> None:
    """Freeze an owned staging tree recursively through retained descriptors."""

    info = os.fstat(descriptor)
    if not stat.S_ISDIR(info.st_mode):
        raise ReleaseError(f"staging object is not a directory: {display}")
    _check_owner(info, uid, gid, display)
    with os.scandir(descriptor) as entries:
        names = sorted(entry.name for entry in entries)
    for name in names:
        child_path = display / name
        child_info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        _check_owner(child_info, uid, gid, child_path)
        if stat.S_ISDIR(child_info.st_mode):
            child = os.open(name, _DIRECTORY_OPEN_FLAGS, dir_fd=descriptor)
            try:
                opened = os.fstat(child)
                if (opened.st_dev, opened.st_ino) != (
                    child_info.st_dev,
                    child_info.st_ino,
                ):
                    raise ReleaseError(
                        f"staging directory changed identity: {child_path}"
                    )
                _freeze_tree_at(child, uid=uid, gid=gid, display=child_path)
            finally:
                os.close(child)
        elif not stat.S_ISREG(child_info.st_mode):
            raise ReleaseError(f"unexpected staging object: {child_path}")
    os.fchmod(descriptor, 0o555)
    os.fsync(descriptor)


class ReleaseInstaller:
    def __init__(
        self,
        layout: Layout,
        *,
        runtime_files: Iterable[str],
        root_files: Mapping[str, str],
        switch_timeout: float = 60.0,
    ) -> None:
        self.layout = layout
        normalized = tuple(sorted({_safe_relpath(path) for path in runtime_files}))
        if not normalized or "grok-remote" not in normalized:
            raise ReleaseError("user release must contain grok-remote")
        if set(root_files) != ROOT_ROLES:
            missing = sorted(ROOT_ROLES - set(root_files))
            extra = sorted(set(root_files) - ROOT_ROLES)
            raise ReleaseError(f"root roles must be exact; missing={missing}, extra={extra}")
        root_normalized = {role: _safe_relpath(path) for role, path in root_files.items()}
        if len(set(root_normalized.values())) != len(ROOT_ROLES):
            raise ReleaseError("root helper roles must map to distinct files")
        if not set(root_normalized.values()).issubset(normalized):
            raise ReleaseError("every root helper must also be in the runtime identity")
        self.runtime_files = normalized
        self.root_files = root_normalized
        if switch_timeout <= 0 or switch_timeout > 300:
            raise ReleaseError("switch timeout must be in (0, 300] seconds")
        self.switch_timeout = float(switch_timeout)

    def validate_apply_prerequisites(self) -> None:
        """Prove fixed privileged runtime dependencies without installing them."""

        path = self.layout.openvpn_binary
        if not path.is_absolute():
            raise ReleaseError("OpenVPN prerequisite path must be absolute")
        if not self.layout.test_install and path != Path("/usr/sbin/openvpn"):
            raise ReleaseError("live OpenVPN prerequisite path is fixed")
        info = _lstat(path)
        expected_uid = self.layout.root_uid if self.layout.test_install else 0
        if (
            info is None
            or stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != expected_uid
            or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not info.st_mode & stat.S_IXUSR
        ):
            raise ReleaseError(
                f"OpenVPN prerequisite is absent or unsafe: {path}; "
                "install a root-owned, non-symlink executable at /usr/sbin/openvpn"
            )

    def _prepare_roots(self) -> None:
        layout = self.layout
        _ensure_dir(layout.root_root, 0o755, layout.root_uid, layout.root_gid)
        _ensure_dir(layout.root_control, 0o755, layout.root_uid, layout.root_gid)
        _ensure_dir(
            layout.runner_scope_root,
            0o700,
            layout.root_uid,
            layout.root_gid,
        )
        _ensure_dir(layout.broker_state, 0o700, layout.root_uid, layout.root_gid)
        _ensure_dir(layout.evidence_root, 0o755, layout.root_uid, layout.root_gid)
        _ensure_dir(layout.rung_evidence_root, 0o755, layout.root_uid, layout.root_gid)
        _ensure_dir(layout.rung_transcript_root, 0o755, layout.root_uid, layout.root_gid)
        _ensure_dir(layout.qualification_root, 0o755, layout.root_uid, layout.root_gid)
        _ensure_dir(layout.boot_inventory_root, 0o755, layout.root_uid, layout.root_gid)
        _ensure_dir(layout.root_releases, 0o755, layout.root_uid, layout.root_gid)
        # Executing as the target user does not imply trusting that user with
        # imported runtime code.  The complete selected tree is root-owned;
        # only mutable per-user state and the containing ~/.local/bin directory
        # remain target-owned.
        _ensure_dir(layout.user_root, 0o755, layout.root_uid, layout.root_gid)
        _ensure_dir(layout.user_releases, 0o755, layout.root_uid, layout.root_gid)
        _ensure_dir(layout.state_root, 0o700, layout.target_uid, layout.target_gid)
        _ensure_dir(layout.entrypoint.parent, 0o755, layout.target_uid, layout.target_gid)
        self._ensure_canary_auth()
        self._ensure_broker_lock()

    @staticmethod
    def _release_access_ids(
        release_ids: str | Iterable[str] | None,
    ) -> frozenset[str]:
        if release_ids is None:
            values: frozenset[str] = frozenset()
        elif isinstance(release_ids, str):
            values = frozenset({release_ids})
        else:
            values = frozenset(release_ids)
        if any(
            not isinstance(value, str)
            or RELEASE_ID_RE.fullmatch(value) is None
            for value in values
        ):
            raise ReleaseError("release access identity is invalid")
        return values

    def _release_access_is_exact(
        self, exposed_release_ids: str | Iterable[str] | None
    ) -> bool:
        descriptor = -1
        try:
            exposed = self._release_access_ids(exposed_release_ids)
            layout = self.layout
            root = layout.user_releases
            descriptor = _open_verified_directory(
                root, 0o755, layout.root_uid, layout.root_gid
            )
            found: set[str] = set()
            with os.scandir(descriptor) as entries:
                for entry in entries:
                    if RELEASE_ID_RE.fullmatch(entry.name) is None:
                        continue
                    info = entry.stat(follow_symlinks=False)
                    if (
                        not stat.S_ISDIR(info.st_mode)
                        or stat.S_ISLNK(info.st_mode)
                        or info.st_uid != layout.root_uid
                        or info.st_gid != layout.root_gid
                    ):
                        return False
                    expected = (
                        ACTIVE_RELEASE_MODE
                        if entry.name in exposed
                        else ARCHIVED_RELEASE_MODE
                    )
                    if stat.S_IMODE(info.st_mode) != expected:
                        return False
                    found.add(entry.name)
            return exposed.issubset(found) and _directory_path_matches(
                root, os.fstat(descriptor)
            )
        except (OSError, ReleaseError):
            return False
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _converge_release_access(
        self, exposed_release_ids: str | Iterable[str] | None
    ) -> None:
        """Expose only explicitly admitted immutable user releases.

        The top directory of every inactive user release is root-only.  Root
        helper trees remain 0555 because the selected broker must inventory
        them during deny-safe crash recovery.  Nested user content remains
        immutable, so rollback can re-enable a validated release with one
        bounded top-directory metadata transition.
        """

        exposed = self._release_access_ids(exposed_release_ids)
        layout = self.layout
        roots = (layout.user_releases,)
        directory_flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        inventories: list[tuple[Path, list[str]]] = []
        for root in roots:
            descriptor = _open_verified_directory(
                root, 0o755, layout.root_uid, layout.root_gid
            )
            try:
                names: list[str] = []
                with os.scandir(descriptor) as entries:
                    for entry in entries:
                        if RELEASE_ID_RE.fullmatch(entry.name) is None:
                            continue
                        info = entry.stat(follow_symlinks=False)
                        path = root / entry.name
                        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(
                            info.st_mode
                        ):
                            raise ReleaseError(
                                f"release access entry is not a safe directory: {path}"
                            )
                        _check_owner(
                            info, layout.root_uid, layout.root_gid, path
                        )
                        mode = stat.S_IMODE(info.st_mode)
                        if mode not in {
                            ACTIVE_RELEASE_MODE,
                            ARCHIVED_RELEASE_MODE,
                        }:
                            raise ReleaseError(
                                f"unexpected release access mode for {path}: {mode:04o}"
                            )
                        names.append(entry.name)
                inventories.append((root, sorted(names)))
            finally:
                os.close(descriptor)
        if any(not exposed.issubset(names) for _root, names in inventories):
            raise ReleaseError(
                "exposed release set is incomplete: " + ",".join(sorted(exposed))
            )

        for root, names in inventories:
            descriptor = _open_verified_directory(
                root, 0o755, layout.root_uid, layout.root_gid
            )
            changed = False
            try:
                ordered = sorted(
                    names,
                    key=lambda name: (name not in exposed, name),
                )
                for name in ordered:
                    desired = (
                        ACTIVE_RELEASE_MODE
                        if name in exposed
                        else ARCHIVED_RELEASE_MODE
                    )
                    try:
                        release_fd = os.open(
                            name, directory_flags, dir_fd=descriptor
                        )
                    except OSError as exc:
                        raise ReleaseError(
                            f"cannot open release for access convergence: {root / name}: {exc}"
                        ) from exc
                    try:
                        info = os.fstat(release_fd)
                        path = root / name
                        if not stat.S_ISDIR(info.st_mode):
                            raise ReleaseError(
                                f"release access entry changed type: {path}"
                            )
                        _check_owner(
                            info, layout.root_uid, layout.root_gid, path
                        )
                        current = stat.S_IMODE(info.st_mode)
                        if current not in {
                            ACTIVE_RELEASE_MODE,
                            ARCHIVED_RELEASE_MODE,
                        }:
                            raise ReleaseError(
                                f"unexpected release access mode for {path}: {current:04o}"
                            )
                        if current != desired:
                            try:
                                os.fchmod(release_fd, desired)
                                os.fsync(release_fd)
                            except OSError as exc:
                                raise ReleaseError(
                                    "cannot durably converge release access: "
                                    f"{path}: {exc}"
                                ) from exc
                            changed = True
                        if stat.S_IMODE(os.fstat(release_fd).st_mode) != desired:
                            raise ReleaseError(
                                f"release access mode did not converge: {path}"
                            )
                    finally:
                        os.close(release_fd)
                if changed:
                    try:
                        os.fsync(descriptor)
                    except OSError as exc:
                        raise ReleaseError(
                            f"cannot fsync release access root {root}: {exc}"
                        ) from exc
                _assert_directory_path_identity(root, descriptor)
            finally:
                os.close(descriptor)
        if not self._release_access_is_exact(exposed):
            raise ReleaseError("release access policy did not converge")

    def _converge_deny_release_access(
        self, deny: Mapping[str, object]
    ) -> None:
        """Archive unrelated releases while keeping existing deny peers usable."""

        exposed: set[str] = set()
        current = self.active_release_id()
        for field in ("from_release", "to_release"):
            value = deny.get(field)
            if value is None and field == "from_release":
                continue
            if not isinstance(value, str) or RELEASE_ID_RE.fullmatch(value) is None:
                raise ReleaseError("deny release access identity is invalid")
            if _present(self.layout.user_releases / value):
                try:
                    self.validate_target_release_pair(value)
                except ReleaseError:
                    # A one-time migration may start from a coherent immutable
                    # legacy selection.  Preserve only that still-selected
                    # source; never re-expose a legacy source after selectors
                    # advance, and never admit a legacy target.
                    self.validate_release_pair(value)
                    if field != "from_release":
                        raise
                    if value != current:
                        continue
                exposed.add(value)
        self._converge_release_access(exposed)

    def _runner_scopes_required(self) -> bool:
        """Return whether this is the fixed live root-controlled layout."""

        return (
            self.layout.root_root == Path("/usr/local/libexec/grok-proxy")
            and self.layout.root_control
            == Path("/var/lib/grok-proxy/release-control")
            and self.layout.root_uid == 0
            and self.layout.root_gid == 0
        ) or self.layout.test_runner_scopes

    def _production_release_layout(self) -> bool:
        """Return whether target admission must use the production byte contract."""

        return (
            self.layout.root_root == Path("/usr/local/libexec/grok-proxy")
            and self.layout.root_control
            == Path("/var/lib/grok-proxy/release-control")
            and self.layout.root_uid == 0
            and self.layout.root_gid == 0
        )

    def _ensure_broker_lock(self) -> None:
        layout = self.layout
        flags = (
            os.O_RDWR
            | os.O_CREAT
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(layout.broker_lock, flags, 0o600)
        except OSError as exc:
            raise ReleaseError(
                f"cannot open fixed broker lock: {layout.broker_lock}: {exc}"
            ) from exc
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise ReleaseError("broker lock is not a regular file")
            _check_owner(
                info,
                layout.root_uid,
                layout.root_gid,
                layout.broker_lock,
            )
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _fsync_dir(layout.broker_state)

    def _ensure_canary_auth(self) -> None:
        layout = self.layout
        flags = (
            os.O_RDWR
            | os.O_CREAT
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(layout.canary_auth, flags, 0o600)
        except OSError as exc:
            raise ReleaseError(
                f"cannot open fixed canary authorization: {layout.canary_auth}: {exc}"
            ) from exc
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise ReleaseError("canary authorization is not a regular file")
            _check_owner(
                info,
                layout.root_uid,
                layout.root_gid,
                layout.canary_auth,
            )
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _fsync_dir(layout.root_control)

    @contextmanager
    def _locked(self):
        """Serialize installer operations without blocking admitted launches."""
        layout = self.layout
        _ensure_dir(layout.root_root, 0o755, layout.root_uid, layout.root_gid)
        _ensure_dir(layout.root_control, 0o755, layout.root_uid, layout.root_gid)
        flags = (
            os.O_RDWR
            | os.O_CREAT
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        fd = os.open(layout.operation_lock, flags, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise ReleaseError(f"operation lock is not regular: {layout.operation_lock}")
            _check_owner(info, layout.root_uid, layout.root_gid, layout.operation_lock)
            os.fchmod(fd, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            self._prepare_roots()
            self._ensure_selection_lock()
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def _ensure_selection_lock(self) -> None:
        layout = self.layout
        flags = (
            os.O_RDWR
            | os.O_CREAT
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        fd = os.open(layout.install_lock, flags, 0o644)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise ReleaseError(
                    f"release selection lock is not regular: {layout.install_lock}"
                )
            _check_owner(info, layout.root_uid, layout.root_gid, layout.install_lock)
            os.fchmod(fd, 0o644)
            os.fsync(fd)
        finally:
            os.close(fd)

    @contextmanager
    def _selection_locked(self, timeout: float = 60.0):
        """Bound selection publication against already-admitted old code."""

        if timeout <= 0:
            raise ReleaseError("selection lock timeout must be positive")
        layout = self.layout
        flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(layout.install_lock, flags)
        locked = False
        deadline = time.monotonic() + timeout
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != layout.root_uid
                or info.st_gid != layout.root_gid
                or stat.S_IMODE(info.st_mode) != 0o644
            ):
                raise ReleaseError("unsafe release selection lock")
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    locked = True
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise ReleaseError(
                            "timed out waiting for admitted old-release commands to exit"
                        )
                    time.sleep(0.02)
            yield
        finally:
            if locked:
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    @staticmethod
    def _fault(fault_at: str | None, stage: str) -> None:
        if fault_at == stage:
            raise InjectedFault(stage)

    def plan_release(self) -> ReleasePlan:
        records: list[FileRecord] = []
        for relpath in self.runtime_files:
            data, source_mode = _read_regular(self.layout.source_dir / relpath)
            installed_mode = 0o555 if source_mode & 0o111 else 0o444
            records.append(
                FileRecord(relpath, _sha256_bytes(data), len(data), installed_mode)
            )
        record_modes = {record.path: record.mode for record in records}
        required_exec = {"grok-remote", *(self.root_files[role] for role in ("broker", "vpngate", "relay"))}
        non_executable = sorted(path for path in required_exec if record_modes.get(path) != 0o555)
        if non_executable:
            raise ReleaseError(f"declared executables lack source execute mode: {non_executable}")
        if record_modes.get(self.root_files["sanitizer"]) != 0o444:
            raise ReleaseError("sanitizer must be non-executable")
        identity: dict[str, object] = {
            "schema_version": SCHEMA_VERSION,
            "handshake_protocol": HANDSHAKE_PROTOCOL,
            "runtime_files": [
                {
                    "path": record.path,
                    "sha256": record.sha256,
                    "size": record.size,
                    "mode": f"{record.mode:04o}",
                }
                for record in records
            ],
            "root_files": [
                {"role": role, "path": path}
                for role, path in sorted(self.root_files.items())
            ],
        }
        release_id = _sha256_bytes(_canonical_json(identity))
        return ReleasePlan(
            release_id,
            tuple(records),
            tuple(sorted(self.root_files.items())),
            identity,
        )

    def _manifest(self, plan: ReleasePlan, kind: str) -> dict[str, object]:
        records = {record.path: record for record in plan.files}
        if kind == "user":
            selected = [(None, record) for record in plan.files]
        elif kind == "root":
            selected = [(role, records[path]) for role, path in plan.root_files]
        else:
            raise ReleaseError(f"unknown release kind: {kind}")
        files: list[dict[str, object]] = []
        for role, record in selected:
            entry: dict[str, object] = {
                "path": record.path,
                "sha256": record.sha256,
                "size": record.size,
                "mode": f"{record.mode:04o}",
            }
            if role is not None:
                entry["role"] = role
            files.append(entry)
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": kind,
            "release_id": plan.release_id,
            "identity": plan.identity,
            "handshake": {
                "protocol": HANDSHAKE_PROTOCOL,
                "release_id": plan.release_id,
                "peer_release_id": plan.release_id,
                "peer_kind": "root" if kind == "user" else "user",
            },
            "files": files,
        }

    @staticmethod
    def _ensure_stage_parent(
        stage: int,
        relative: PurePosixPath,
        *,
        uid: int,
        gid: int,
        display: Path,
    ) -> int:
        """Return an opened staging subdirectory, creating it beneath ``stage``."""

        descriptor = os.dup(stage)
        current = display
        try:
            for part in relative.parts:
                if part in {"", ".", ".."}:
                    raise ReleaseError(f"unsafe staging directory component: {part!r}")
                current = current / part
                try:
                    os.mkdir(part, 0o755, dir_fd=descriptor)
                except FileExistsError:
                    pass
                child = os.open(part, _DIRECTORY_OPEN_FLAGS, dir_fd=descriptor)
                try:
                    info = os.fstat(child)
                    if not stat.S_ISDIR(info.st_mode):
                        raise ReleaseError(f"unsafe staging directory: {current}")
                    _check_owner(info, uid, gid, current)
                    os.fchmod(child, 0o755)
                except BaseException:
                    os.close(child)
                    raise
                os.close(descriptor)
                descriptor = child
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def _copy_record(
        self,
        source: Path,
        expected: FileRecord,
        stage: int,
        stage_path: Path,
        uid: int,
        gid: int,
    ) -> None:
        data, _ = _read_regular(source)
        if len(data) != expected.size or _sha256_bytes(data) != expected.sha256:
            raise ReleaseError(f"runtime source changed while staging: {source}")
        relative = PurePosixPath(expected.path)
        parent_relative = relative.parent
        if parent_relative == PurePosixPath("."):
            parent_relative = PurePosixPath()
        destination = stage_path / expected.path
        parent = self._ensure_stage_parent(
            stage,
            parent_relative,
            uid=uid,
            gid=gid,
            display=stage_path,
        )
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            fd = os.open(relative.name, flags, 0o600, dir_fd=parent)
            try:
                os.fchown(fd, uid, gid)
                os.fchmod(fd, expected.mode)
                _write_all(fd, data, destination)
                os.fsync(fd)
                opened = os.fstat(fd)
                named = os.stat(
                    relative.name, dir_fd=parent, follow_symlinks=False
                )
                if (
                    not stat.S_ISREG(named.st_mode)
                    or (named.st_dev, named.st_ino)
                    != (opened.st_dev, opened.st_ino)
                    or (named.st_uid, named.st_gid) != (uid, gid)
                    or stat.S_IMODE(named.st_mode) != expected.mode
                ):
                    raise ReleaseError(
                        f"staged file changed identity: {destination}"
                    )
            finally:
                os.close(fd)
            os.fsync(parent)
        finally:
            os.close(parent)

    def _stage_release(self, plan: ReleasePlan, kind: str) -> tuple[Path | None, Path]:
        layout = self.layout
        if kind == "user":
            releases, uid, gid = layout.user_releases, layout.root_uid, layout.root_gid
        else:
            releases, uid, gid = layout.root_releases, layout.root_uid, layout.root_gid
        releases_fd = _open_verified_directory(releases, 0o755, uid, gid)
        final = releases / plan.release_id
        try:
            try:
                os.stat(plan.release_id, dir_fd=releases_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                _assert_directory_path_identity(releases, releases_fd)
                self._validate_release(final, plan.release_id, kind)
                return None, final

            with os.scandir(releases_fd) as entries:
                stale_names = sorted(
                    entry.name
                    for entry in entries
                    if entry.name.startswith(f".stage-{plan.release_id}-")
                )
            for stale_name in stale_names:
                _remove_tree_at(
                    releases_fd,
                    stale_name,
                    uid=uid,
                    gid=gid,
                    display=releases / stale_name,
                )

            stage_name = f".stage-{plan.release_id}-{uuid.uuid4().hex}"
            stage_path = releases / stage_name
            os.mkdir(stage_name, 0o700, dir_fd=releases_fd)
            stage_fd = os.open(stage_name, _DIRECTORY_OPEN_FLAGS, dir_fd=releases_fd)
            try:
                stage_info = os.fstat(stage_fd)
                if not stat.S_ISDIR(stage_info.st_mode):
                    raise ReleaseError(f"staging object is not a directory: {stage_path}")
                os.fchown(stage_fd, uid, gid)
                os.fchmod(stage_fd, 0o700)
                os.fsync(stage_fd)
                os.fsync(releases_fd)

                record_by_path = {record.path: record for record in plan.files}
                selections = (
                    [(None, record) for record in plan.files]
                    if kind == "user"
                    else [(role, record_by_path[path]) for role, path in plan.root_files]
                )
                for _role, record in selections:
                    self._copy_record(
                        layout.source_dir / record.path,
                        record,
                        stage_fd,
                        stage_path,
                        uid,
                        gid,
                    )
                manifest_data = _canonical_json(self._manifest(plan, kind)) + b"\n"
                manifest_fd = os.open(
                    "release.json",
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=stage_fd,
                )
                try:
                    os.fchown(manifest_fd, uid, gid)
                    os.fchmod(manifest_fd, 0o444)
                    _write_all(manifest_fd, manifest_data, stage_path / "release.json")
                    os.fsync(manifest_fd)
                finally:
                    os.close(manifest_fd)
                _freeze_tree_at(stage_fd, uid=uid, gid=gid, display=stage_path)
                named_stage = os.stat(
                    stage_name, dir_fd=releases_fd, follow_symlinks=False
                )
                frozen_stage = os.fstat(stage_fd)
                if (
                    (named_stage.st_dev, named_stage.st_ino)
                    != (stage_info.st_dev, stage_info.st_ino)
                    or (frozen_stage.st_dev, frozen_stage.st_ino)
                    != (stage_info.st_dev, stage_info.st_ino)
                    or stat.S_IMODE(frozen_stage.st_mode) != 0o555
                ):
                    raise ReleaseError(f"staging tree changed identity: {stage_path}")
                os.fsync(releases_fd)
                _assert_directory_path_identity(releases, releases_fd)
            finally:
                os.close(stage_fd)
            return stage_path, final
        except BaseException:
            try:
                if "stage_name" in locals():
                    os.stat(
                        stage_name, dir_fd=releases_fd, follow_symlinks=False
                    )
                    _remove_tree_at(
                        releases_fd,
                        stage_name,
                        uid=uid,
                        gid=gid,
                        display=releases / stage_name,
                    )
            except FileNotFoundError:
                pass
            raise
        finally:
            os.close(releases_fd)

    def _publish_stage(self, stage: Path | None, final: Path) -> None:
        if stage is None:
            return
        if stage.parent != final.parent or stage.name == final.name:
            raise ReleaseError("staging publication paths are invalid")
        parent = _open_verified_directory(
            final.parent,
            0o755,
            self.layout.root_uid,
            self.layout.root_gid,
        )
        try:
            staged = os.stat(stage.name, dir_fd=parent, follow_symlinks=False)
            if (
                not stat.S_ISDIR(staged.st_mode)
                or (staged.st_uid, staged.st_gid)
                != (self.layout.root_uid, self.layout.root_gid)
                or stat.S_IMODE(staged.st_mode) != 0o555
            ):
                raise ReleaseError(f"unsafe staging publication object: {stage}")
            try:
                os.stat(final.name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ReleaseError(f"release destination already exists: {final}")
            os.rename(
                stage.name,
                final.name,
                src_dir_fd=parent,
                dst_dir_fd=parent,
            )
            published = os.stat(
                final.name, dir_fd=parent, follow_symlinks=False
            )
            if (published.st_dev, published.st_ino) != (
                staged.st_dev,
                staged.st_ino,
            ):
                raise ReleaseError(f"release publication changed identity: {final}")
            os.fsync(parent)
            _assert_directory_path_identity(final.parent, parent)
        finally:
            os.close(parent)

    @staticmethod
    def _read_json(
        path: Path,
        *,
        uid: int | None = None,
        gid: int | None = None,
        mode: int | None = None,
    ) -> dict[str, object]:
        raw, _ = _read_regular(path, uid=uid, gid=gid, mode=mode, maximum=1024 * 1024)
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, ValueError) as exc:
            raise ReleaseError(f"cannot parse JSON metadata {path}: {exc}") from exc
        if not isinstance(value, dict):
            raise ReleaseError(f"metadata is not an object: {path}")
        return value

    def _validate_release(self, directory: Path, release_id: str, kind: str) -> dict[str, object]:
        if not RELEASE_ID_RE.fullmatch(release_id):
            raise ReleaseError(f"invalid release ID: {release_id!r}")
        layout = self.layout
        uid, gid = layout.root_uid, layout.root_gid
        if kind == "user":
            _verify_release_dir(directory, uid, gid)
        else:
            _verify_dir(directory, ACTIVE_RELEASE_MODE, uid, gid)
        manifest = self._read_json(directory / "release.json", uid=uid, gid=gid, mode=0o444)
        if set(manifest) != {"schema_version", "kind", "release_id", "identity", "handshake", "files"}:
            raise ReleaseError(f"unexpected manifest fields in {directory}")
        if manifest.get("schema_version") != SCHEMA_VERSION:
            raise ReleaseError(f"wrong manifest schema in {directory}")
        if manifest.get("kind") != kind or manifest.get("release_id") != release_id:
            raise ReleaseError(f"release manifest identity mismatch in {directory}")
        identity = manifest.get("identity")
        if not isinstance(identity, dict) or _sha256_bytes(_canonical_json(identity)) != release_id:
            raise ReleaseError(f"release identity hash mismatch in {directory}")
        handshake = manifest.get("handshake")
        if not isinstance(handshake, dict) or handshake != {
            "protocol": HANDSHAKE_PROTOCOL,
            "release_id": release_id,
            "peer_release_id": release_id,
            "peer_kind": "root" if kind == "user" else "user",
        }:
            raise ReleaseError(f"release handshake mismatch in {directory}")
        entries = manifest.get("files")
        if not isinstance(entries, list) or not entries:
            raise ReleaseError(f"empty file manifest in {directory}")
        expected_paths: set[str] = set()
        roles: set[str] = set()
        for entry in entries:
            if not isinstance(entry, dict):
                raise ReleaseError(f"invalid file manifest entry in {directory}")
            allowed = {"path", "sha256", "size", "mode"} | ({"role"} if kind == "root" else set())
            if set(entry) != allowed:
                raise ReleaseError(f"unexpected file manifest fields in {directory}")
            relpath = _safe_relpath(str(entry.get("path", "")))
            if relpath in expected_paths:
                raise ReleaseError(f"duplicate manifest path in {directory}: {relpath}")
            expected_paths.add(relpath)
            try:
                expected_mode = int(str(entry["mode"]), 8)
                expected_size = int(entry["size"])
                expected_hash = str(entry["sha256"])
            except (KeyError, TypeError, ValueError) as exc:
                raise ReleaseError(f"invalid file metadata for {relpath}") from exc
            if expected_mode not in (0o444, 0o555) or expected_size < 0 or not RELEASE_ID_RE.fullmatch(expected_hash):
                raise ReleaseError(f"invalid file bounds for {relpath}")
            data, _ = _read_regular(
                directory / relpath, uid=uid, gid=gid, mode=expected_mode
            )
            if len(data) != expected_size or _sha256_bytes(data) != expected_hash:
                raise ReleaseError(f"release file mismatch: {directory / relpath}")
            if kind == "root":
                role = entry.get("role")
                if not isinstance(role, str) or role not in ROOT_ROLES or role in roles:
                    raise ReleaseError(f"invalid or duplicate root helper role in {directory}")
                roles.add(role)
        actual_files: set[str] = set()
        actual_dirs: set[str] = set()
        for path in directory.rglob("*"):
            info = path.lstat()
            _check_owner(info, uid, gid, path)
            rel = path.relative_to(directory).as_posix()
            if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
                if stat.S_IMODE(info.st_mode) != 0o555:
                    raise ReleaseError(f"release directory is mutable: {path}")
                actual_dirs.add(rel)
            elif stat.S_ISREG(info.st_mode):
                actual_files.add(rel)
            else:
                raise ReleaseError(f"unexpected release object: {path}")
        expected_dirs = {
            PurePosixPath(path).parents[index].as_posix()
            for path in expected_paths
            for index in range(len(PurePosixPath(path).parents) - 1)
            if PurePosixPath(path).parents[index].as_posix() != "."
        }
        if actual_files != expected_paths | {"release.json"} or actual_dirs != expected_dirs:
            raise ReleaseError(f"unexpected or missing release objects in {directory}")
        if kind == "root" and roles != ROOT_ROLES:
            raise ReleaseError(f"root helper roles are incomplete in {directory}")
        if kind == "user" and "grok-remote" not in expected_paths:
            raise ReleaseError(f"user release lacks grok-remote: {directory}")
        return manifest

    def validate_release_pair(self, release_id: str) -> tuple[dict[str, object], dict[str, object]]:
        user = self._validate_release(self.layout.user_releases / release_id, release_id, "user")
        root = self._validate_release(self.layout.root_releases / release_id, release_id, "root")
        if user.get("identity") != root.get("identity"):
            raise ReleaseError(f"user/root release identity mismatch: {release_id}")
        identity = user["identity"]
        assert isinstance(identity, dict)
        if set(identity) != {"schema_version", "handshake_protocol", "runtime_files", "root_files"}:
            raise ReleaseError(f"unexpected identity fields: {release_id}")
        runtime_entries = identity.get("runtime_files")
        root_entries = identity.get("root_files")
        user_files = user.get("files")
        root_files = root.get("files")
        if not all(isinstance(value, list) for value in (runtime_entries, root_entries, user_files, root_files)):
            raise ReleaseError(f"invalid release identity lists: {release_id}")
        assert isinstance(runtime_entries, list) and isinstance(root_entries, list)
        assert isinstance(user_files, list) and isinstance(root_files, list)
        user_projection = [
            {key: entry[key] for key in ("path", "sha256", "size", "mode")}
            for entry in user_files
        ]
        root_projection = sorted(
            [{"role": entry["role"], "path": entry["path"]} for entry in root_files],
            key=lambda entry: (str(entry["role"]), str(entry["path"])),
        )
        if user_projection != runtime_entries or root_projection != root_entries:
            raise ReleaseError(f"release manifests do not match hashed identity: {release_id}")
        self._root_files_from_identity(identity, release_id)
        return user, root

    def validate_target_release_pair(
        self, release_id: str
    ) -> tuple[dict[str, object], dict[str, object]]:
        """Validate a pair that is eligible to become executable again."""

        user, root = self.validate_release_pair(release_id)
        entries = user.get("files")
        if not isinstance(entries, list) or not any(
            isinstance(entry, dict)
            and entry.get("path") == DIRECT_ADMISSION_RUNTIME
            and entry.get("mode") == "0444"
            for entry in entries
        ):
            raise ReleaseError(
                "release predates mandatory direct self-admission and cannot be selected: "
                f"{release_id}"
            )
        if self._production_release_layout():
            contents: dict[str, bytes] = {}
            for relative in DIRECT_ADMISSION_PRODUCTION_SHA256:
                mode = (
                    0o555
                    if relative in {"grok-remote", "egress.sh"}
                    else 0o444
                )
                contents[relative], _source_mode = _read_regular(
                    self.layout.user_releases / release_id / relative,
                    uid=self.layout.root_uid,
                    gid=self.layout.root_gid,
                    mode=mode,
                    maximum=16 * 1024 * 1024,
                )
            if not _production_direct_admission_is_exact(contents):
                raise ReleaseError(
                    "release has an unrecognized production direct-admission contract: "
                    f"{release_id}"
                )
        return user, root

    @staticmethod
    def _root_files_from_identity(
        identity: Mapping[str, object], release_id: str
    ) -> dict[str, str]:
        entries = identity.get("root_files")
        if not isinstance(entries, list):
            raise ReleaseError(f"invalid root helper identity: {release_id}")
        result: dict[str, str] = {}
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {"role", "path"}:
                raise ReleaseError(f"invalid root helper identity entry: {release_id}")
            role = entry.get("role")
            path = entry.get("path")
            if type(role) is not str or role not in ROOT_ROLES or role in result:
                raise ReleaseError(f"invalid root helper identity role: {release_id}")
            if type(path) is not str:
                raise ReleaseError(f"invalid root helper identity path: {release_id}")
            result[role] = _safe_relpath(path)
        if set(result) != ROOT_ROLES or len(set(result.values())) != len(ROOT_ROLES):
            raise ReleaseError(f"incomplete or aliased root helper identity: {release_id}")
        return dict(sorted(result.items()))

    def _target_root_files(self, release_id: str) -> dict[str, str]:
        user, _root = self.validate_target_release_pair(release_id)
        identity = user.get("identity")
        assert isinstance(identity, dict)
        return self._root_files_from_identity(identity, release_id)

    def _bound_target_root_files(
        self,
        release_id: str,
        supplied: Mapping[str, str] | None,
    ) -> dict[str, str]:
        embedded = self._target_root_files(release_id)
        if supplied is None:
            return embedded
        normalized = {role: _safe_relpath(path) for role, path in supplied.items()}
        if normalized != embedded:
            raise ReleaseError(
                f"target root helper map differs from release identity: {release_id}"
            )
        return embedded

    def _selector_id(self, path: Path, uid: int, gid: int, parent_mode: int) -> str | None:
        directory = _open_verified_directory(path.parent, parent_mode, uid, gid)
        try:
            try:
                info = os.stat(
                    path.name, dir_fd=directory, follow_symlinks=False
                )
            except FileNotFoundError:
                return None
            if not stat.S_ISLNK(info.st_mode):
                raise ReleaseError(f"selector is not a symlink: {path}")
            _check_owner(info, uid, gid, path)
            target = os.readlink(path.name, dir_fd=directory)
            candidate = PurePosixPath(target)
            if len(candidate.parts) != 2 or candidate.parts[0] != "releases":
                raise ReleaseError(f"unsafe selector target: {path} -> {target!r}")
            release_id = candidate.parts[1]
            if not RELEASE_ID_RE.fullmatch(release_id):
                raise ReleaseError(f"invalid selector release: {release_id!r}")
            _assert_directory_path_identity(path.parent, directory)
            return release_id
        finally:
            os.close(directory)

    def active_release_id(self) -> str | None:
        return self._selector_id(
            self.layout.current,
            self.layout.root_uid,
            self.layout.root_gid,
            0o755,
        )

    def root_active_release_id(self) -> str | None:
        return self._selector_id(
            self.layout.root_current,
            self.layout.root_uid,
            self.layout.root_gid,
            0o755,
        )

    def _gate_source(
        self,
        release_id: str,
        kind: str,
        *,
        target_root_files: Mapping[str, str] | None = None,
    ) -> bytes:
        """Return a deterministic, pinned, self-validating exec gate."""
        if kind not in ("user", "broker"):
            raise ReleaseError(f"unknown gate kind: {kind}")
        layout = self.layout
        selected_root_files = self._bound_target_root_files(
            release_id, target_root_files
        )
        constants = {
            "EXPECTED": release_id,
            "KIND": kind,
            "USER_ROOT": str(layout.user_root),
            "ROOT_ROOT": str(layout.root_root),
            "USER_SELECTED": str(layout.selected),
            "ROOT_SELECTED": str(layout.root_selected),
            "DENY": str(layout.rollback_deny),
            "LOCK": str(layout.install_lock),
            "CANARY_AUTH": str(layout.canary_auth),
            "EVIDENCE_ROOT": str(layout.evidence_root),
            "RUNG_EVIDENCE_ROOT": str(layout.root_control / "rung-evidence"),
            "RUNG_TRANSCRIPT_ROOT": str(layout.root_control / "rung-transcripts"),
            "QUALIFICATION_ROOT": str(layout.root_control / "qualification"),
            "RUNG_CANARY": str(layout.root_control / "rung-canary.json"),
            "CANARY_TERMINAL": str(layout.canary_terminal),
            "BOOT_INVENTORY": str(
                layout.root_control / "boot-inventory" / f"{release_id}.json"
            ),
            "BROKER_STATE": str(layout.broker_state),
            "ENTRYPOINT": str(layout.entrypoint),
            "BROKER_GATE": str(layout.broker_entrypoint),
            "TARGET_UID": layout.target_uid,
            "TARGET_GID": layout.target_gid,
            "ROOT_UID": layout.root_uid,
            "ROOT_GID": layout.root_gid,
            "TEST_INSTALL": layout.test_install,
            "RELEASE_SCHEMA": SCHEMA_VERSION,
            "CONTROL_SCHEMA": CONTROL_SCHEMA_VERSION,
            "EVIDENCE_SCHEMA": EVIDENCE_SCHEMA_VERSION,
            "RUNG_EVIDENCE_SCHEMA": RUNG_EVIDENCE_SCHEMA_VERSION,
            "RUNG_CANARY_SCHEMA": RUNG_CANARY_SCHEMA_VERSION,
            "RUNG_TRANSCRIPT_SCHEMA": RUNG_TRANSCRIPT_SCHEMA_VERSION,
            "QUALIFICATION_RESULT_SCHEMA": QUALIFICATION_RESULT_SCHEMA_VERSION,
            "RELEASE_QUALIFICATION_SCHEMA": RELEASE_QUALIFICATION_SCHEMA_VERSION,
            "BOOT_INVENTORY_SCHEMA": BOOT_INVENTORY_SCHEMA_VERSION,
            "PROTOCOL": HANDSHAKE_PROTOCOL,
            "ROOT_FILES": selected_root_files,
            "REQUIRED_CRITERIA": EVIDENCE_CRITERIA,
            # Never embed a set/frozenset repr: its hash-seed-dependent order
            # would make otherwise identical gates differ across processes.
            "RUNG_MEASUREMENT_FIELDS": tuple(sorted(RUNG_MEASUREMENT_FIELDS)),
            "RUNG_RECORD_FIELDS": tuple(sorted(RUNG_RECORD_FIELDS)),
            "CANARY_BINDINGS": CANARY_ENV_BINDINGS,
            "HOST_ID": self._host_id(),
            "ZERO_DIGEST": ZERO_DIGEST,
        }
        prefix = "".join(f"{name}={value!r}\n" for name, value in constants.items())
        body = r'''import fcntl
import hashlib
import json
import os
import re
import stat
import sys

RID = re.compile(r"^[0-9a-f]{64}$")
RUNG = re.compile(r"^(?:direct|iphone|vpn|home:[A-Za-z0-9._:+@-]{1,120})$")
ROUTE_PROFILE = re.compile(r"^(?:direct|iphone|vpn|auto|auto-no-direct|home:[A-Za-z0-9._:+@-]{1,120})$")
GROK_RELEASE = re.compile(r"^[A-Za-z0-9._:+@-]{1,128}$")
MODEL_ID = re.compile(r"^[A-Za-z0-9._:+/@-]{1,128}$")
BOOT = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

def fail(reason):
    label = "grok-remote" if KIND == "user" else "vpn-broker"
    print(f"{label}: release selection unavailable: {reason}", file=sys.stderr)
    raise SystemExit(78)

def info(path):
    try:
        return os.lstat(path)
    except OSError as exc:
        fail(f"cannot inspect {path}: {exc}")

def owner_mode(value, path, uid, gid, mode, object_type):
    if value.st_uid != uid or value.st_gid != gid or stat.S_IMODE(value.st_mode) != mode:
        fail(f"unsafe owner/mode for {path}")
    if object_type == "dir" and not stat.S_ISDIR(value.st_mode):
        fail(f"not a directory: {path}")
    if object_type == "file" and not stat.S_ISREG(value.st_mode):
        fail(f"not a regular file: {path}")
    if object_type == "link" and not stat.S_ISLNK(value.st_mode):
        fail(f"not a selector link: {path}")

def read_file(path, uid, gid, mode):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        fail(f"cannot open {path}: {exc}")
    try:
        value = os.fstat(fd)
        owner_mode(value, path, uid, gid, mode, "file")
        chunks = []
        total = 0
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > 1024 * 1024:
                fail(f"oversized metadata: {path}")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)

def read_json(path, uid, gid, mode):
    try:
        value = json.loads(read_file(path, uid, gid, mode))
    except (UnicodeDecodeError, ValueError) as exc:
        fail(f"invalid JSON in {path}: {exc}")
    if not isinstance(value, dict):
        fail(f"metadata is not an object: {path}")
    return value

def resource_proves(step, observations):
    contract_fields = {
        "expected_owned_processes", "max_owned_fds", "max_owned_threads",
        "max_owned_vmrss_kib", "max_owned_vmsize_kib",
        "max_cgroup_pids_delta", "max_cgroup_memory_delta_bytes",
        "post_pids_tolerance", "post_memory_tolerance_bytes",
    }
    observed_fields = {
        "peak_owned_processes", "peak_owned_fds", "peak_owned_threads",
        "peak_owned_vmrss_kib", "peak_owned_vmsize_kib",
        "cgroup_pids_delta", "cgroup_memory_delta_bytes",
        "cgroup_pids_highwater_delta",
        "cgroup_memory_highwater_delta_bytes", "memory_event_delta_total",
        "pids_event_delta_total", "post_owned_processes", "post_owned_fds",
        "post_owned_threads", "post_owned_vmrss_kib",
        "post_owned_vmsize_kib", "post_pids_delta", "post_memory_delta_bytes",
    }
    contract = observations.get("resource_contract")
    observed = observations.get("resource_observed")
    host_digest = observations.get("host_limits_sha256")
    maximum = (1 << 63) - 1
    if (
        type(contract) is not dict or set(contract) != contract_fields
        or type(observed) is not dict or set(observed) != observed_fields
        or type(host_digest) is not str or RID.fullmatch(host_digest) is None
        or host_digest == ZERO_DIGEST
        or any(type(value) is not int or not 0 <= value <= maximum for value in contract.values())
    ):
        return False
    signed = {"post_pids_delta", "post_memory_delta_bytes"}
    if any(
        type(value) is not int
        or not ((-maximum <= value <= maximum) if name in signed else (0 <= value <= maximum))
        for name, value in observed.items()
    ):
        return False
    count = 32 if step == "load32" else 1
    expected = {
        "expected_owned_processes": 2 * count + 2 if step == "load32" else 5,
        "max_owned_fds": 256 + 40 * count,
        "max_owned_threads": 96 + 12 * count,
        "max_owned_vmrss_kib": 768 * 1024 + count * 96 * 1024,
        "max_owned_vmsize_kib": 4 * 1024 * 1024 + count * 512 * 1024,
        "max_cgroup_pids_delta": 48 + 6 * count,
        "max_cgroup_memory_delta_bytes": 768 * 1024 * 1024 + count * 96 * 1024 * 1024,
        "post_pids_tolerance": 16,
        "post_memory_tolerance_bytes": 512 * 1024 * 1024,
    }
    return (
        contract == expected
        and observed["peak_owned_processes"] == expected["expected_owned_processes"]
        and observed["peak_owned_fds"] <= expected["max_owned_fds"]
        and observed["peak_owned_threads"] <= expected["max_owned_threads"]
        and observed["peak_owned_vmrss_kib"] <= expected["max_owned_vmrss_kib"]
        and observed["peak_owned_vmsize_kib"] <= expected["max_owned_vmsize_kib"]
        and observed["cgroup_pids_delta"] <= expected["max_cgroup_pids_delta"]
        and observed["cgroup_pids_highwater_delta"] <= expected["max_cgroup_pids_delta"]
        and observed["cgroup_memory_delta_bytes"] <= expected["max_cgroup_memory_delta_bytes"]
        and observed["cgroup_memory_highwater_delta_bytes"] <= expected["max_cgroup_memory_delta_bytes"]
        and observed["memory_event_delta_total"] == 0
        and observed["pids_event_delta_total"] == 0
        and all(observed[name] == 0 for name in (
            "post_owned_processes", "post_owned_fds", "post_owned_threads",
            "post_owned_vmrss_kib", "post_owned_vmsize_kib",
        ))
        and observed["post_pids_delta"] <= expected["post_pids_tolerance"]
        and observed["post_memory_delta_bytes"] <= expected["post_memory_tolerance_bytes"]
    )

def fixed_qualification(path, step, nonce, canary_kind, rung, route_profile, grok_release, model_id, contract=None):
    raw = read_file(path, ROOT_UID, ROOT_GID, 0o444)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, ValueError) as exc:
        fail(f"invalid fixed qualification result: {exc}")
    canonical = (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
    common = {
        "schema_version", "kind", "step", "release_id", "canary_nonce",
        "canary_kind", "rung", "route_profile", "contract_sha256", "grok_release_id",
        "model_id", "status", "started_unix_ns", "completed_unix_ns",
        "duration_ms", "observations", "error_code", "error_sha256",
    }
    if (
        raw != canonical
        or not isinstance(value, dict)
        or set(value) != common
        or value.get("schema_version") != QUALIFICATION_RESULT_SCHEMA
        or value.get("kind") != "grok-multi-session-qualification"
        or value.get("step") != step
        or value.get("release_id") != EXPECTED
        or value.get("canary_nonce") != nonce
        or value.get("canary_kind") != canary_kind
        or value.get("rung") != rung
        or value.get("route_profile") != route_profile
        or value.get("grok_release_id") != grok_release
        or value.get("model_id") != model_id
        or type(value.get("contract_sha256")) is not str
        or RID.fullmatch(value["contract_sha256"]) is None
        or (contract is not None and value.get("contract_sha256") != contract)
        or value.get("status") != "passed"
        or value.get("error_code") is not None
        or value.get("error_sha256") is not None
        or type(value.get("started_unix_ns")) is not int
        or value.get("started_unix_ns", 0) <= 0
        or type(value.get("completed_unix_ns")) is not int
        or value.get("completed_unix_ns", 0) < value.get("started_unix_ns", 0)
        or type(value.get("duration_ms")) is not int
        or not 0 <= value.get("duration_ms", -1) <= 900000
        or not isinstance(value.get("observations"), dict)
    ):
        fail("fixed qualification result is failed or mismatched")
    observations = value["observations"]
    detail = observations.get("detail_sha256")
    if type(detail) is not str or RID.fullmatch(detail) is None:
        fail("fixed qualification detail digest is invalid")
    if step == "load32":
        expected_observations = {
            "clients_requested", "clients_completed", "active_rung",
            "shared_owner_epoch", "shared_generation", "shared_contract",
            "unique_leaders", "overload_rejected", "byte_path_verified",
            "host_limits_captured", "resource_gate_passed", "cleanup_proved",
            "ready_duration_ms", "detail_sha256", "host_limits_sha256",
            "resource_contract", "resource_observed",
        }
        true_fields = {
            "shared_owner_epoch", "shared_generation", "shared_contract",
            "overload_rejected", "byte_path_verified", "host_limits_captured",
            "resource_gate_passed", "cleanup_proved",
        }
        valid = (
            set(observations) == expected_observations
            and observations.get("clients_requested") == 32
            and observations.get("clients_completed") == 32
            and observations.get("active_rung") == "direct"
            and observations.get("unique_leaders") == 32
            and all(observations.get(name) is True for name in true_fields)
            and type(observations.get("ready_duration_ms")) is int
            and 0 <= observations.get("ready_duration_ms", -1) <= 900000
            and resource_proves(step, observations)
        )
    elif step == "fault-recovery":
        expected_observations = {
            "active_rung", "supervisor_loss_exact", "wrapper_failed_closed",
            "descendant_contained", "first_recovery_applied",
            "second_recovery_noop", "recovery_duration_ms",
            "resource_gate_passed", "cleanup_proved", "detail_sha256",
            "host_limits_sha256", "resource_contract", "resource_observed",
        }
        true_fields = {
            "supervisor_loss_exact", "wrapper_failed_closed",
            "descendant_contained", "first_recovery_applied",
            "second_recovery_noop", "resource_gate_passed", "cleanup_proved",
        }
        valid = (
            set(observations) == expected_observations
            and observations.get("active_rung") == "direct"
            and all(observations.get(name) is True for name in true_fields)
            and type(observations.get("recovery_duration_ms")) is int
            and 0 <= observations.get("recovery_duration_ms", -1) <= 900000
            and resource_proves(step, observations)
        )
    elif step == "real-pair":
        expected_observations = {
            "sessions_requested", "sessions_completed", "active_rung", "model_id",
            "shared_owner_epoch", "shared_generation", "shared_contract",
            "independent_grok_units", "shared_leader_disabled",
            "leader_socket_count", "unique_session_ids", "outputs_valid",
            "exit_codes_zero", "cache_before_valid", "cache_during_valid",
            "cache_after_valid", "cache_identity_safe",
            "provider_fault_authenticated", "single_repair_observed",
            "clients_survived_repair", "reconnect_duration_ms",
            "transport_duration_ms", "cleanup_proved", "detail_sha256",
            "blocked_reason",
        }
        true_fields = {
            "shared_owner_epoch", "shared_generation", "shared_contract",
            "shared_leader_disabled",
            "outputs_valid", "exit_codes_zero", "cache_before_valid",
            "cache_during_valid", "cache_after_valid", "cache_identity_safe",
            "provider_fault_authenticated", "single_repair_observed",
            "clients_survived_repair", "cleanup_proved",
        }
        valid = (
            set(observations) == expected_observations
            and observations.get("sessions_requested") == 2
            and observations.get("sessions_completed") == 2
            and observations.get("active_rung") == rung
            and observations.get("model_id") == model_id
            and observations.get("independent_grok_units") == 2
            and observations.get("leader_socket_count") == 0
            and observations.get("unique_session_ids") == 2
            and all(observations.get(name) is True for name in true_fields)
            and type(observations.get("reconnect_duration_ms")) is int
            and 0 <= observations.get("reconnect_duration_ms", -1) <= 900000
            and type(observations.get("transport_duration_ms")) is int
            and 0 <= observations.get("transport_duration_ms", -1) <= 900000
            and observations.get("blocked_reason") is None
        )
    else:
        valid = False
    if not valid:
        fail("fixed qualification observations do not prove their step")
    return value, hashlib.sha256(raw).hexdigest()

def selector(path, uid, gid, expected):
    owner_mode(info(path), path, uid, gid, 0o777, "link")
    target = os.readlink(path)
    if target != f"releases/{expected}":
        fail(f"mixed selector: {path}")

def cleanup_broker_request(argv):
    if KIND != "broker":
        return False
    operations = []
    modes = []
    index = 0
    while index < len(argv):
        item = argv[index]
        if item in {"--operation", "--mode"}:
            if index + 1 >= len(argv):
                return False
            (operations if item == "--operation" else modes).append(argv[index + 1])
            index += 2
            continue
        if item.startswith("--operation="):
            operations.append(item.split("=", 1)[1])
        elif item.startswith("--mode="):
            modes.append(item.split("=", 1)[1])
        index += 1
    if len(operations) != 1:
        return False
    if operations[0] in {"down", "recover", "status"}:
        return True
    if operations[0] != "migrate-legacy" or modes != ["compatibility-handoff"]:
        return False
    if not os.path.lexists(DENY):
        return False
    deny = read_json(DENY, ROOT_UID, ROOT_GID, 0o444)
    return (
        set(deny) == {"schema_version", "operation", "from_release", "to_release"}
        and deny.get("schema_version") == CONTROL_SCHEMA
        and deny.get("operation") == "canary"
        and deny.get("from_release") == EXPECTED
        and deny.get("to_release") == EXPECTED
    )

def broker_arguments(argv):
    known = {
        "--operation", "--mode", "--release-id", "--owner-epoch",
        "--generation", "--listen-port", "--contract-digest",
        "--vpn-max-tries", "--vpn-ranking-version", "--vpn-countries",
        "--vpn-prefer-countries", "--vpn-blocked-countries",
        "--caller-pid", "--caller-start-ticks", "--caller-boot-id",
        "--deadline-monotonic-ns",
    }
    values = {}
    index = 0
    while index < len(argv):
        item = argv[index]
        if item in known:
            if index + 1 >= len(argv):
                return None
            if item in values:
                return None
            values[item] = argv[index + 1]
            index += 2
            continue
        if item.startswith("--") and "=" in item:
            name, value = item.split("=", 1)
            if name not in known or name in values:
                return None
            values[name] = value
            index += 1
            continue
        return None
    return values

def broker_rung_canary_request(argv):
    if (
        KIND != "broker"
        or not os.path.lexists(DENY)
        or os.path.lexists(CANARY_TERMINAL)
    ):
        return False
    arguments = broker_arguments(argv)
    if arguments is None:
        return False
    operation = arguments.get("--operation")
    mode = arguments.get("--mode")
    release_id = arguments.get("--release-id")
    contract = arguments.get("--contract-digest")
    if (
        operation not in {"up", "next"}
        or mode != "supervisor"
        or release_id != EXPECTED
        or type(contract) is not str
        or RID.fullmatch(contract) is None
    ):
        return False
    deny = read_json(DENY, ROOT_UID, ROOT_GID, 0o444)
    if (
        set(deny) != {"schema_version", "operation", "from_release", "to_release"}
        or deny.get("schema_version") != CONTROL_SCHEMA
        or deny.get("operation") != "canary"
        or deny.get("from_release") != EXPECTED
        or deny.get("to_release") != EXPECTED
    ):
        return False
    record = read_json(RUNG_CANARY, ROOT_UID, ROOT_GID, 0o444)
    fields = {
        "schema_version", "release_id", "host_id", "rung", "route_profile",
        "contract_sha256", "grok_release_id", "model_id", "canary_kind",
        "canary_nonce", "created_unix_ns",
    }
    route_profile = record.get("route_profile")
    return (
        set(record) == fields
        and record.get("schema_version") == RUNG_CANARY_SCHEMA
        and record.get("release_id") == EXPECTED
        and record.get("host_id") == HOST_ID
        and record.get("rung") == "vpn"
        and route_profile in {"vpn", "auto", "auto-no-direct"}
        and record.get("contract_sha256") == contract
        and record.get("canary_kind") == "rung"
        and type(record.get("grok_release_id")) is str
        and GROK_RELEASE.fullmatch(record["grok_release_id"]) is not None
        and type(record.get("model_id")) is str
        and MODEL_ID.fullmatch(record["model_id"]) is not None
        and type(record.get("canary_nonce")) is str
        and RID.fullmatch(record["canary_nonce"]) is not None
        and type(record.get("created_unix_ns")) is int
        and record.get("created_unix_ns", 0) > 0
    )

def public_recovery_request(argv):
    return KIND == "user" and argv == ["recover"]

def canary_command_class(argv):
    if not argv:
        return "gated"
    first = argv[0]
    if first in {"-h", "--help", "help"}:
        return "usage"
    if first in {"inspect", "--version", "version", "completions", "worktree", "leader"}:
        return "bare"
    if first in {"stop", "iphone-setup"}:
        return "maintenance"
    if first in {"status", "ip"} and len(argv) == 1:
        return "control"
    if argv == ["recover"]:
        return "recovery"
    index = 0
    while index < len(argv):
        item = argv[index]
        if item == "--host":
            if index + 1 >= len(argv):
                return "gated"
            index += 2
            continue
        if item in {"--iphone", "--vpn", "--no-direct", "--pick-model", "--direct"}:
            index += 1
            continue
        if item == "--":
            index += 1
        break
    if index < len(argv) and argv[index] in {"completions", "worktree", "leader"}:
        return "bare"
    return "gated"

def canary_request(argv):
    local_allowed = (
        argv in (["--help"], ["--version"], ["status"], ["--release-compatibility-smoke"])
        if KIND == "user"
        else argv in (
            ["--release-selection-smoke"],
            ["--release-root-inventory"],
            ["--release-bootstrap-migrate"],
        )
    )
    rung_requested = KIND == "user" and os.environ.get("GROK_RELEASE_RUNG_CANARY") == "1"
    if not local_allowed and not rung_requested:
        return None
    raw = os.environ.get("GROK_RELEASE_CANARY_FD", "")
    if not raw.isascii() or not raw.isdecimal() or int(raw) < 3:
        return None
    descriptor = int(raw)
    try:
        actual = os.fstat(descriptor)
        expected = info(CANARY_AUTH)
    except OSError:
        return None
    if (
        not stat.S_ISREG(actual.st_mode)
        or not stat.S_ISREG(expected.st_mode)
        or actual.st_uid != ROOT_UID
        or actual.st_gid != ROOT_GID
        or stat.S_IMODE(actual.st_mode) != 0o600
        or expected.st_uid != ROOT_UID
        or expected.st_gid != ROOT_GID
        or stat.S_IMODE(expected.st_mode) != 0o600
        or (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino)
    ):
        return None
    if not rung_requested:
        return descriptor, "local"
    record = read_json(RUNG_CANARY, ROOT_UID, ROOT_GID, 0o444)
    fields = {
        "schema_version", "release_id", "host_id", "rung", "route_profile",
        "contract_sha256", "grok_release_id", "model_id", "canary_kind",
        "canary_nonce", "created_unix_ns",
    }
    rung = os.environ.get("GROK_RELEASE_CANARY_RUNG")
    route_profile = os.environ.get("GROK_RELEASE_CANARY_ROUTE_PROFILE")
    contract = os.environ.get("GROK_RELEASE_CANARY_CONTRACT")
    grok_release = os.environ.get("GROK_RELEASE_CANARY_GROK_RELEASE")
    model_id = os.environ.get("GROK_RELEASE_CANARY_MODEL")
    canary_kind = os.environ.get("GROK_RELEASE_CANARY_KIND")
    canary_nonce = os.environ.get("GROK_RELEASE_CANARY_NONCE")
    if (
        set(record) != fields
        or record.get("schema_version") != RUNG_CANARY_SCHEMA
        or record.get("release_id") != EXPECTED
        or record.get("host_id") != HOST_ID
        or record.get("rung") != rung
        or type(rung) is not str
        or RUNG.fullmatch(rung) is None
        or record.get("route_profile") != route_profile
        or type(route_profile) is not str
        or ROUTE_PROFILE.fullmatch(route_profile) is None
        or not (
            route_profile == rung
            or route_profile == "auto"
            or (route_profile == "auto-no-direct" and rung != "direct")
        )
        or record.get("canary_kind") != canary_kind
        or canary_kind not in {"release", "rung"}
        or not (
            (
                canary_kind == "release"
                and contract is None
                and record.get("contract_sha256") is None
                and rung == "direct"
                and route_profile == "direct"
            )
            or (
                canary_kind == "rung"
                and type(contract) is str
                and RID.fullmatch(contract) is not None
                and record.get("contract_sha256") == contract
            )
        )
        or record.get("grok_release_id") != grok_release
        or type(grok_release) is not str
        or GROK_RELEASE.fullmatch(grok_release) is None
        or record.get("model_id") != model_id
        or type(model_id) is not str
        or MODEL_ID.fullmatch(model_id) is None
        or record.get("canary_nonce") != canary_nonce
        or type(canary_nonce) is not str
        or RID.fullmatch(canary_nonce) is None
        or type(record.get("created_unix_ns")) is not int
        or record.get("created_unix_ns", 0) <= 0
    ):
        fail("rung canary authorization record is invalid")
    if canary_command_class(argv) in {"usage", "bare", "maintenance"}:
        fail("rung canary command class is forbidden")
    return descriptor, "rung"

if os.geteuid() != (TARGET_UID if KIND == "user" else ROOT_UID):
    fail("wrong effective user")

try:
    lock_fd = os.open(LOCK, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
except OSError as exc:
    fail(f"cannot open release lock: {exc}")
lock_info = os.fstat(lock_fd)
if not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid != ROOT_UID or lock_info.st_gid != ROOT_GID or stat.S_IMODE(lock_info.st_mode) != 0o644:
    fail("unsafe release lock")
fcntl.flock(lock_fd, fcntl.LOCK_SH)

canary = canary_request(sys.argv[1:])
if canary is None and any(name in os.environ for name in CANARY_BINDINGS):
    fail("incomplete release/rung canary authorization")
canary_fd = canary[0] if canary is not None else None
rung_canary = canary is not None and canary[1] == "rung"
broker_cleanup = cleanup_broker_request(sys.argv[1:])
broker_rung_canary = broker_rung_canary_request(sys.argv[1:])
public_recovery = public_recovery_request(sys.argv[1:])
root_inventory = (
    KIND == "broker"
    and canary_fd is not None
    and sys.argv[1:] in (
        ["--release-root-inventory"],
        ["--release-bootstrap-migrate"],
    )
)
deny_safe = (
    broker_cleanup
    or broker_rung_canary
    or public_recovery
    or canary_fd is not None
)
if os.path.lexists(DENY) and not deny_safe:
    fail("durable install/rollback deny is active")
evidence_recovery_bypass = (
    os.path.lexists(DENY) and (broker_cleanup or public_recovery or root_inventory)
)

root_raw = read_file(ROOT_SELECTED, ROOT_UID, ROOT_GID, 0o444)
user_raw = read_file(USER_SELECTED, TARGET_UID, TARGET_GID, 0o444)
try:
    root_record = json.loads(root_raw)
    user_record = json.loads(user_raw)
except (UnicodeDecodeError, ValueError) as exc:
    fail(f"invalid selection metadata: {exc}")
if not isinstance(root_record, dict) or not isinstance(user_record, dict):
    fail("selection metadata is not an object")
user_hash = root_record.pop("user_selection_sha256", None)
if user_hash != hashlib.sha256(user_raw).hexdigest() or root_record != user_record:
    fail("root/user selection records differ")
if root_record.get("schema_version") != CONTROL_SCHEMA or root_record.get("release_schema_version") != RELEASE_SCHEMA or root_record.get("handshake_protocol") != PROTOCOL:
    fail("selection protocol mismatch")
if root_record.get("release_id") != EXPECTED or not RID.fullmatch(EXPECTED):
    fail("gate/selection release mismatch")
if root_record.get("user_release_id") != EXPECTED or root_record.get("root_release_id") != EXPECTED:
    fail("mixed release identity")
if root_record.get("root_files") != ROOT_FILES:
    fail("root helper map mismatch")
selection_phase = root_record.get("selection_phase")
evidence_sha256 = root_record.get("evidence_sha256")
qualified_rungs = root_record.get("qualified_rungs")
if broker_rung_canary and (
    selection_phase != "READY" or evidence_sha256 == ZERO_DIGEST
):
    fail("VPN rung canary requires the exact READY selection")
if not evidence_recovery_bypass and not isinstance(qualified_rungs, list):
    fail("qualified rung selection is not an array")
if selection_phase == "CANARY":
    if evidence_sha256 != ZERO_DIGEST or not os.path.lexists(DENY) or not deny_safe or rung_canary:
        fail("incomplete canary selection is not recovery/canary authorized")
elif selection_phase != "READY":
    fail("selection evidence phase/digest is invalid")
elif not evidence_recovery_bypass and (
    not isinstance(evidence_sha256, str) or not RID.fullmatch(evidence_sha256)
):
    fail("selection evidence phase/digest is invalid")
if (
    KIND == "broker"
    and sys.argv[1:] == ["--release-bootstrap-migrate"]
    and (
        selection_phase != "CANARY"
        or root_record.get("operation") != "install"
    )
):
    fail("bootstrap migration requires the exact CANARY install selection")

selector(os.path.join(USER_ROOT, "current"), ROOT_UID, ROOT_GID, EXPECTED)
selector(os.path.join(ROOT_ROOT, "current"), ROOT_UID, ROOT_GID, EXPECTED)
user_release = os.path.join(USER_ROOT, "releases", EXPECTED)
root_release = os.path.join(ROOT_ROOT, "releases", EXPECTED)
owner_mode(info(user_release), user_release, ROOT_UID, ROOT_GID, 0o555, "dir")
owner_mode(info(root_release), root_release, ROOT_UID, ROOT_GID, 0o555, "dir")
user_manifest_raw = read_file(os.path.join(user_release, "release.json"), ROOT_UID, ROOT_GID, 0o444)
root_manifest_raw = read_file(os.path.join(root_release, "release.json"), ROOT_UID, ROOT_GID, 0o444)
if hashlib.sha256(user_manifest_raw).hexdigest() != root_record.get("user_manifest_sha256"):
    fail("user manifest digest mismatch")
if hashlib.sha256(root_manifest_raw).hexdigest() != root_record.get("root_manifest_sha256"):
    fail("root manifest digest mismatch")
if hashlib.sha256(read_file(ENTRYPOINT, ROOT_UID, ROOT_GID, 0o555)).hexdigest() != root_record.get("entrypoint_sha256"):
    fail("entrypoint gate digest mismatch")
if hashlib.sha256(read_file(BROKER_GATE, ROOT_UID, ROOT_GID, 0o555)).hexdigest() != root_record.get("broker_gate_sha256"):
    fail("broker gate digest mismatch")
if selection_phase == "READY" and not evidence_recovery_bypass:
    evidence_raw = read_file(
        os.path.join(EVIDENCE_ROOT, EXPECTED + ".json"),
        ROOT_UID,
        ROOT_GID,
        0o444,
    )
    if hashlib.sha256(evidence_raw).hexdigest() != evidence_sha256:
        fail("promotion evidence digest mismatch")
    try:
        evidence = json.loads(evidence_raw)
    except (UnicodeDecodeError, ValueError) as exc:
        fail(f"invalid promotion evidence: {exc}")
    evidence_fields = {
        "schema_version", "release_id", "operation", "host_id",
        "created_unix_ns", "user_manifest_sha256", "root_manifest_sha256",
        "root_files", "criteria", "overall_pass",
    }
    if not isinstance(evidence, dict) or set(evidence) != evidence_fields:
        fail("promotion evidence has an unexpected shape")
    if (
        evidence.get("schema_version") != EVIDENCE_SCHEMA
        or evidence.get("release_id") != EXPECTED
        or evidence.get("operation") != root_record.get("operation")
        or evidence.get("host_id") != HOST_ID
        or type(evidence.get("created_unix_ns")) is not int
        or evidence.get("created_unix_ns", 0) <= 0
        or evidence.get("user_manifest_sha256") != root_record.get("user_manifest_sha256")
        or evidence.get("root_manifest_sha256") != root_record.get("root_manifest_sha256")
        or evidence.get("root_files") != ROOT_FILES
        or evidence.get("overall_pass") is not True
    ):
        fail("promotion evidence does not bind the selected release")
    criteria = evidence.get("criteria")
    if not isinstance(criteria, list) or len(criteria) != len(REQUIRED_CRITERIA):
        fail("promotion evidence criteria are incomplete")
    for expected_id, criterion in zip(REQUIRED_CRITERIA, criteria):
        if (
            not isinstance(criterion, dict)
            or set(criterion) != {"id", "passed", "result_sha256", "duration_ms"}
            or criterion.get("id") != expected_id
            or criterion.get("passed") is not True
            or not isinstance(criterion.get("result_sha256"), str)
            or not RID.fullmatch(criterion["result_sha256"])
            or type(criterion.get("duration_ms")) is not int
            or not 0 <= criterion["duration_ms"] <= 300_000
        ):
            fail("promotion evidence criterion failed or mismatched")

if not evidence_recovery_bypass:
    normalized_rungs = []
    identities = set()
    owner_mode(info(RUNG_EVIDENCE_ROOT), RUNG_EVIDENCE_ROOT, ROOT_UID, ROOT_GID, 0o755, "dir")
    release_rung_root = os.path.join(RUNG_EVIDENCE_ROOT, EXPECTED)
    if qualified_rungs:
        owner_mode(info(release_rung_root), release_rung_root, ROOT_UID, ROOT_GID, 0o755, "dir")
    for record in qualified_rungs:
        if not isinstance(record, dict) or set(record) != set(RUNG_RECORD_FIELDS):
            fail("qualified rung record has an unexpected shape")
        rung = record.get("rung")
        contract = record.get("contract_sha256")
        grok_release = record.get("grok_release_id")
        rung_evidence_sha = record.get("evidence_sha256")
        if (
            type(rung) is not str or RUNG.fullmatch(rung) is None
            or type(contract) is not str or RID.fullmatch(contract) is None
            or type(grok_release) is not str or GROK_RELEASE.fullmatch(grok_release) is None
            or type(rung_evidence_sha) is not str or RID.fullmatch(rung_evidence_sha) is None
        ):
            fail("qualified rung identity is invalid")
        identity = (rung, contract, grok_release)
        if identity in identities:
            fail("qualified rung identity is duplicated")
        identities.add(identity)
        rung_raw = read_file(
            os.path.join(release_rung_root, rung_evidence_sha + ".json"),
            ROOT_UID,
            ROOT_GID,
            0o444,
        )
        if hashlib.sha256(rung_raw).hexdigest() != rung_evidence_sha:
            fail("qualified rung evidence digest mismatch")
        try:
            rung_evidence = json.loads(rung_raw)
        except (UnicodeDecodeError, ValueError) as exc:
            fail(f"invalid qualified rung evidence: {exc}")
        rung_fields = {
            "schema_version", "release_id", "host_id", "rung",
            "route_profile", "contract_sha256", "grok_release_id", "model_id",
            "measured_unix_ns", "canary_nonce",
            "release_qualification_sha256", "real_pair_result_sha256",
            "measurements", "overall_pass",
        }
        measurements = rung_evidence.get("measurements") if isinstance(rung_evidence, dict) else None
        canary_nonce = rung_evidence.get("canary_nonce") if isinstance(rung_evidence, dict) else None
        model_id = rung_evidence.get("model_id") if isinstance(rung_evidence, dict) else None
        route_profile = rung_evidence.get("route_profile") if isinstance(rung_evidence, dict) else None
        release_qualification_sha = rung_evidence.get("release_qualification_sha256") if isinstance(rung_evidence, dict) else None
        real_pair_sha = rung_evidence.get("real_pair_result_sha256") if isinstance(rung_evidence, dict) else None
        if (
            not isinstance(rung_evidence, dict)
            or set(rung_evidence) != rung_fields
            or rung_evidence.get("schema_version") != RUNG_EVIDENCE_SCHEMA
            or rung_evidence.get("release_id") != EXPECTED
            or rung_evidence.get("host_id") != HOST_ID
            or rung_evidence.get("rung") != rung
            or type(route_profile) is not str or ROUTE_PROFILE.fullmatch(route_profile) is None
            or not (
                route_profile == rung
                or route_profile == "auto"
                or (route_profile == "auto-no-direct" and rung != "direct")
            )
            or rung_evidence.get("contract_sha256") != contract
            or rung_evidence.get("grok_release_id") != grok_release
            or type(model_id) is not str or MODEL_ID.fullmatch(model_id) is None
            or type(canary_nonce) is not str or RID.fullmatch(canary_nonce) is None
            or type(release_qualification_sha) is not str or RID.fullmatch(release_qualification_sha) is None
            or type(real_pair_sha) is not str or RID.fullmatch(real_pair_sha) is None
            or type(rung_evidence.get("measured_unix_ns")) is not int
            or rung_evidence.get("measured_unix_ns", 0) <= 0
            or not isinstance(measurements, dict)
            or set(measurements) != set(RUNG_MEASUREMENT_FIELDS)
            or any(measurements.get(field) is not True for field in RUNG_MEASUREMENT_FIELDS if field not in {"duration_ms", "result_sha256"})
            or type(measurements.get("duration_ms")) is not int
            or not 1 <= measurements.get("duration_ms", 0) <= 2700000
            or type(measurements.get("result_sha256")) is not str
            or RID.fullmatch(measurements["result_sha256"]) is None
            or rung_evidence.get("overall_pass") is not True
        ):
            fail("qualified rung evidence is failed or mismatched")
        qualification_dir = os.path.join(QUALIFICATION_ROOT, EXPECTED)
        owner_mode(info(QUALIFICATION_ROOT), QUALIFICATION_ROOT, ROOT_UID, ROOT_GID, 0o755, "dir")
        owner_mode(info(qualification_dir), qualification_dir, ROOT_UID, ROOT_GID, 0o755, "dir")
        try:
            qualification_entries = sorted(os.listdir(qualification_dir))
        except OSError as exc:
            fail(f"cannot list release qualification: {exc}")
        if qualification_entries != ["fault-recovery.json", "load32.json", "release.json"]:
            fail("release qualification step set is incomplete or contains residue")
        release_state_raw = read_file(os.path.join(qualification_dir, "release.json"), ROOT_UID, ROOT_GID, 0o444)
        if hashlib.sha256(release_state_raw).hexdigest() != release_qualification_sha:
            fail("release qualification digest mismatch")
        try:
            release_state = json.loads(release_state_raw)
        except (UnicodeDecodeError, ValueError) as exc:
            fail(f"invalid release qualification state: {exc}")
        release_fields = {
            "schema_version", "release_id", "host_id", "boot_id", "canary_nonce",
            "contract_sha256", "grok_release_id", "model_id", "step_sha256s",
            "entrypoint_sha256", "broker_gate_sha256",
            "qualified_unix_ns", "overall_pass",
        }
        if (
            not isinstance(release_state, dict)
            or set(release_state) != release_fields
            or release_state.get("schema_version") != RELEASE_QUALIFICATION_SCHEMA
            or release_state.get("release_id") != EXPECTED
            or release_state.get("host_id") != HOST_ID
            or type(release_state.get("boot_id")) is not str
            or BOOT.fullmatch(release_state["boot_id"]) is None
            or type(release_state.get("canary_nonce")) is not str
            or RID.fullmatch(release_state["canary_nonce"]) is None
            or type(release_state.get("contract_sha256")) is not str
            or RID.fullmatch(release_state["contract_sha256"]) is None
            or release_state.get("entrypoint_sha256") != root_record.get("entrypoint_sha256")
            or release_state.get("broker_gate_sha256") != root_record.get("broker_gate_sha256")
            or type(release_state.get("grok_release_id")) is not str
            or GROK_RELEASE.fullmatch(release_state["grok_release_id"]) is None
            or release_state.get("model_id") != "grok-4.5"
            or type(release_state.get("qualified_unix_ns")) is not int
            or release_state.get("qualified_unix_ns", 0) <= 0
            or release_state.get("overall_pass") is not True
        ):
            fail("release qualification state is failed or mismatched")
        fake_raw = read_file(
            os.path.join(user_release, "grok_ms", "qualification_fake_grok.py"),
            ROOT_UID, ROOT_GID, 0o555,
        )
        if release_state.get("grok_release_id") != "sha256:" + hashlib.sha256(fake_raw).hexdigest():
            fail("release qualification fake Grok identity mismatch")
        release_results = []
        step_digests = {}
        for step in ("load32", "fault-recovery"):
            result, result_sha = fixed_qualification(
                os.path.join(qualification_dir, step + ".json"), step,
                release_state["canary_nonce"], "release", "direct", "direct",
                release_state["grok_release_id"], release_state["model_id"],
            )
            if result.get("contract_sha256") != release_state.get("contract_sha256"):
                fail("release qualification contract differs between steps")
            release_results.append(result)
            step_digests[step] = result_sha
        if release_state.get("step_sha256s") != step_digests:
            fail("release qualification step digests mismatch")
        release_transcript_root = os.path.join(RUNG_TRANSCRIPT_ROOT, EXPECTED)
        nonce_transcript_root = os.path.join(release_transcript_root, canary_nonce)
        owner_mode(info(RUNG_TRANSCRIPT_ROOT), RUNG_TRANSCRIPT_ROOT, ROOT_UID, ROOT_GID, 0o755, "dir")
        owner_mode(info(release_transcript_root), release_transcript_root, ROOT_UID, ROOT_GID, 0o755, "dir")
        owner_mode(info(nonce_transcript_root), nonce_transcript_root, ROOT_UID, ROOT_GID, 0o755, "dir")
        try:
            actual_entries = sorted(os.listdir(nonce_transcript_root))
        except OSError as exc:
            fail(f"cannot list rung qualification results: {exc}")
        if "real-pair.json" not in actual_entries or any(
            name != "real-pair.json" and re.fullmatch(r"[0-9a-f]{64}\.json", name) is None
            for name in actual_entries
        ):
            fail("rung qualification result set contains residue")
        real_result, actual_real_sha = fixed_qualification(
            os.path.join(nonce_transcript_root, "real-pair.json"), "real-pair",
            canary_nonce, "rung", rung, route_profile, grok_release, model_id, contract,
        )
        if actual_real_sha != real_pair_sha:
            fail("real-pair qualification digest mismatch")
        derived_result = hashlib.sha256(
            (json.dumps(
                {"real_pair_result_sha256": real_pair_sha, "release_qualification_sha256": release_qualification_sha},
                sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            ) + "\n").encode("ascii")
        ).hexdigest()
        expected_duration = max(1, sum(item["duration_ms"] for item in release_results) + real_result["duration_ms"])
        if measurements.get("result_sha256") != derived_result or measurements.get("duration_ms") != expected_duration:
            fail("rung measurement is not derived from fixed qualification results")
        normalized_rungs.append(record)
    if qualified_rungs != sorted(
        normalized_rungs,
        key=lambda value: (
            value["rung"], value["contract_sha256"], value["grok_release_id"]
        ),
    ):
        fail("qualified rung selection is not canonical")

    feature_on = KIND == "user" and os.environ.get("GROK_MULTI_SESSION") == "1"
    broker_mutation = KIND == "broker" and not broker_cleanup and canary_fd is None
    if feature_on or broker_mutation:
        boot_inventory = read_json(BOOT_INVENTORY, ROOT_UID, ROOT_GID, 0o444)
        try:
            with open("/proc/sys/kernel/random/boot_id", "r", encoding="ascii") as handle:
                running_boot = handle.read(64).strip()
        except OSError as exc:
            fail(f"cannot read boot identity: {exc}")
        if (
            set(boot_inventory) != {
                "schema_version", "release_id", "host_id", "boot_id",
                "checked_unix_ns", "inventory_sha256",
            }
            or boot_inventory.get("schema_version") != BOOT_INVENTORY_SCHEMA
            or boot_inventory.get("release_id") != EXPECTED
            or boot_inventory.get("host_id") != HOST_ID
            or boot_inventory.get("boot_id") != running_boot
            or type(boot_inventory.get("checked_unix_ns")) is not int
            or boot_inventory.get("checked_unix_ns", 0) <= 0
            or type(boot_inventory.get("inventory_sha256")) is not str
            or RID.fullmatch(str(boot_inventory.get("inventory_sha256"))) is None
        ):
            fail("current-boot root inventory has not been revalidated")

manifest_raw = user_manifest_raw if KIND == "user" else root_manifest_raw
try:
    manifest = json.loads(manifest_raw)
except (UnicodeDecodeError, ValueError) as exc:
    fail(f"invalid release manifest: {exc}")
if manifest.get("release_id") != EXPECTED or manifest.get("schema_version") != RELEASE_SCHEMA:
    fail("release manifest identity mismatch")
target_rel = "grok-remote" if KIND == "user" else ROOT_FILES["broker"]
matches = [entry for entry in manifest.get("files", []) if isinstance(entry, dict) and entry.get("path") == target_rel]
if len(matches) != 1:
    fail("selected executable is absent or duplicated")
entry = matches[0]
if KIND == "broker" and entry.get("role") != "broker":
    fail("selected root executable is not the broker role")
target = os.path.join(user_release if KIND == "user" else root_release, target_rel)
target_raw = read_file(
    target,
    ROOT_UID,
    ROOT_GID,
    0o555,
)
if len(target_raw) != entry.get("size") or hashlib.sha256(target_raw).hexdigest() != entry.get("sha256"):
    fail("selected executable digest mismatch")
if os.path.lexists(DENY) and not deny_safe:
    fail("durable deny appeared during admission")
if broker_rung_canary and not broker_rung_canary_request(sys.argv[1:]):
    fail("VPN rung canary authorization changed during admission")
if KIND == "broker" and canary_fd is not None and sys.argv[1:] == ["--release-selection-smoke"]:
    print(json.dumps({
        "active": False,
        "release_id": EXPECTED,
        "root_files": ROOT_FILES,
        "status": "selection-coherent",
    }, sort_keys=True, separators=(",", ":")))
    raise SystemExit(0)
if KIND == "broker" and canary_fd is not None and sys.argv[1:] in (
    ["--release-root-inventory"],
    ["--release-bootstrap-migrate"],
):
    try:
        os.set_inheritable(canary_fd, True)
    except OSError as exc:
        fail(f"cannot preserve root inventory authorization: {exc}")
    inventory_env = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/root",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "GROK_RELEASE_INVENTORY_FD": str(canary_fd),
        "GROK_RELEASE_INVENTORY_RELEASE_ID": EXPECTED,
    }
    if TEST_INSTALL:
        inventory_env.update({
            "GROK_TESTING": "1",
            "GROK_TEST_ROOT_RELEASE_CONTROL": os.path.dirname(ROOT_SELECTED),
            "GROK_TEST_ROOT_ROOT": ROOT_ROOT,
            "GROK_TEST_BROKER_STATE": BROKER_STATE,
        })
    os.execve(target, [target, *sys.argv[1:]], inventory_env)
# Keep the shared selection lock across exec.  This closes the interval between
# admitting the selected user release and its publication of recovery.fence;
# after that point the fence is the durable switch interlock.  Broker children
# also remain pinned to this selection for the duration of their transaction.
try:
    os.set_inheritable(lock_fd, True)
except OSError as exc:
    fail(f"cannot preserve release lock across exec: {exc}")
argv = [target, *sys.argv[1:]]
if KIND == "broker":
    clean_env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}
    for name in ("SUDO_UID", "SUDO_GID"):
        value = os.environ.get(name, "")
        if value.isascii() and value.isdigit():
            clean_env[name] = value
    sudo_user = os.environ.get("SUDO_USER", "")
    if sudo_user and sudo_user.isascii() and all(character.isalnum() or character in "_-" for character in sudo_user):
        clean_env["SUDO_USER"] = sudo_user
    os.execve(target, argv, clean_env)
user_env = dict(os.environ)
user_env["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin"
user_env["GROK_RELEASE_LOCK_FD"] = str(lock_fd)
if canary_fd is not None:
    try:
        os.set_inheritable(canary_fd, True)
    except OSError as exc:
        fail(f"cannot preserve canary authorization across exec: {exc}")
    user_env["GROK_RELEASE_CANARY_MODE"] = "1"
    user_env["GROK_RELEASE_CANARY_FD"] = str(canary_fd)
    user_env["GROK_RELEASE_CANARY_RELEASE_ID"] = EXPECTED
    if not rung_canary:
        preserved = {
            "GROK_RELEASE_CANARY_MODE",
            "GROK_RELEASE_CANARY_FD",
            "GROK_RELEASE_CANARY_RELEASE_ID",
        }
        for name in CANARY_BINDINGS:
            if name not in preserved:
                user_env.pop(name, None)
else:
    for name in CANARY_BINDINGS:
        user_env.pop(name, None)
if TEST_INSTALL and user_env.get("GROK_TESTING") == "1":
    user_env["GROK_TEST_ROOT_RELEASE_CONTROL"] = os.path.dirname(ROOT_SELECTED)
for name in tuple(user_env):
    if (
        ((name == "GROK_TESTING" or name.startswith("GROK_TEST_")) and not TEST_INSTALL)
        or name.startswith("LD_")
        or name in {
            "BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS",
            "PYTHONPATH", "PYTHONHOME",
        }
    ):
        user_env.pop(name, None)
os.execve("/bin/bash", ["/bin/bash", "-p", target, *sys.argv[1:]], user_env)
'''
        # Isolated mode prevents PYTHONPATH/user-site injection into the root gate.
        return ("#!/usr/bin/python3 -I\n" + prefix + body).encode("utf-8")

    def _selection_records(
        self,
        release_id: str,
        operation: str,
        entrypoint_bytes: bytes,
        broker_bytes: bytes,
        *,
        target_root_files: Mapping[str, str] | None = None,
        evidence_sha256: str,
        selection_phase: str,
        qualified_rungs: Iterable[Mapping[str, object]] = (),
    ) -> tuple[dict[str, object], dict[str, object]]:
        user_manifest = self.layout.user_releases / release_id / "release.json"
        root_manifest = self.layout.root_releases / release_id / "release.json"
        selected_root_files = self._bound_target_root_files(
            release_id, target_root_files
        )
        if RELEASE_ID_RE.fullmatch(evidence_sha256) is None:
            raise ReleaseError("selection evidence digest is invalid")
        if selection_phase not in {"CANARY", "READY"}:
            raise ReleaseError("selection phase is invalid")
        if (selection_phase == "CANARY") != (evidence_sha256 == ZERO_DIGEST):
            raise ReleaseError("selection evidence phase/digest disagree")
        normalized_rungs = self._normalize_qualified_rungs(qualified_rungs)
        if selection_phase == "CANARY" and normalized_rungs:
            raise ReleaseError("canary selection cannot claim qualified rungs")
        base: dict[str, object] = {
            "schema_version": CONTROL_SCHEMA_VERSION,
            "release_schema_version": SCHEMA_VERSION,
            "handshake_protocol": HANDSHAKE_PROTOCOL,
            "release_id": release_id,
            "user_release_id": release_id,
            "root_release_id": release_id,
            "user_manifest_sha256": _sha256_bytes(
                _read_regular(user_manifest, uid=self.layout.root_uid, gid=self.layout.root_gid, mode=0o444)[0]
            ),
            "root_manifest_sha256": _sha256_bytes(
                _read_regular(root_manifest, uid=self.layout.root_uid, gid=self.layout.root_gid, mode=0o444)[0]
            ),
            "entrypoint_sha256": _sha256_bytes(entrypoint_bytes),
            "broker_gate_sha256": _sha256_bytes(broker_bytes),
            "root_files": selected_root_files,
            "evidence_sha256": evidence_sha256,
            "qualified_rungs": normalized_rungs,
            "selection_phase": selection_phase,
            "target_uid": self.layout.target_uid,
            "target_gid": self.layout.target_gid,
            "user_root": str(self.layout.user_root),
            "root_root": str(self.layout.root_root),
            "root_control": str(self.layout.root_control),
            "operation": operation,
        }
        user_bytes = _canonical_json(base) + b"\n"
        root = dict(base)
        root["user_selection_sha256"] = _sha256_bytes(user_bytes)
        return base, root

    @staticmethod
    def _normalize_qualified_rungs(
        records: Iterable[Mapping[str, object]],
    ) -> list[dict[str, str]]:
        normalized: list[dict[str, str]] = []
        identities: set[tuple[str, str, str]] = set()
        for record in records:
            if not isinstance(record, Mapping) or set(record) != RUNG_RECORD_FIELDS:
                raise ReleaseError("qualified rung record has an unexpected shape")
            rung = record.get("rung")
            contract = record.get("contract_sha256")
            grok_release = record.get("grok_release_id")
            evidence = record.get("evidence_sha256")
            if type(rung) is not str or RUNG_TOKEN_RE.fullmatch(rung) is None:
                raise ReleaseError("qualified rung name is invalid")
            if type(contract) is not str or RELEASE_ID_RE.fullmatch(contract) is None:
                raise ReleaseError("qualified rung contract digest is invalid")
            if (
                type(grok_release) is not str
                or GROK_RELEASE_RE.fullmatch(grok_release) is None
            ):
                raise ReleaseError("qualified rung Grok release identity is invalid")
            if type(evidence) is not str or RELEASE_ID_RE.fullmatch(evidence) is None:
                raise ReleaseError("qualified rung evidence digest is invalid")
            identity = (rung, contract, grok_release)
            if identity in identities:
                raise ReleaseError("qualified rung identity is duplicated")
            identities.add(identity)
            normalized.append(
                {
                    "contract_sha256": contract,
                    "evidence_sha256": evidence,
                    "grok_release_id": grok_release,
                    "rung": rung,
                }
            )
        return sorted(
            normalized,
            key=lambda value: (
                value["rung"],
                value["contract_sha256"],
                value["grok_release_id"],
            ),
        )

    def _validate_rung_transcript_value(
        self,
        value: object,
        *,
        release_id: str,
        nonce: str,
        rung: str,
        contract_sha256: str,
        grok_release_id: str,
        expected_digest: str,
    ) -> dict[str, object]:
        fields = {
            "schema_version",
            "transcript_kind",
            "release_id",
            "host_id",
            "rung",
            "contract_sha256",
            "grok_release_id",
            "canary_nonce",
            "run_id",
            "argv_sha256",
            "environment_sha256",
            "started_unix_ns",
            "completed_unix_ns",
            "duration_ms",
            "returncode",
            "passed",
        }
        if (
            not isinstance(value, dict)
            or set(value) != fields
            or value.get("schema_version") != RUNG_TRANSCRIPT_SCHEMA_VERSION
            or value.get("transcript_kind") != "manual"
            or value.get("release_id") != release_id
            or value.get("host_id") != self._host_id()
            or value.get("rung") != rung
            or value.get("contract_sha256") != contract_sha256
            or value.get("grok_release_id") != grok_release_id
            or value.get("canary_nonce") != nonce
            or type(value.get("run_id")) is not str
            or RUN_ID_RE.fullmatch(str(value.get("run_id"))) is None
            or type(value.get("argv_sha256")) is not str
            or RELEASE_ID_RE.fullmatch(str(value.get("argv_sha256"))) is None
            or type(value.get("environment_sha256")) is not str
            or RELEASE_ID_RE.fullmatch(str(value.get("environment_sha256"))) is None
            or type(value.get("started_unix_ns")) is not int
            or value.get("started_unix_ns", 0) <= 0
            or type(value.get("completed_unix_ns")) is not int
            or value.get("completed_unix_ns", 0) < value.get("started_unix_ns", 0)
            or type(value.get("duration_ms")) is not int
            or not 0 <= value.get("duration_ms", -1) <= 86_400_000
            or type(value.get("returncode")) is not int
            or not -255 <= value.get("returncode", -256) <= 255
            or value.get("passed") is not (value.get("returncode") == 0)
            or RELEASE_ID_RE.fullmatch(expected_digest) is None
        ):
            raise ReleaseError("rung execution transcript is invalid or mismatched")
        return value

    def _rung_transcript_digests(
        self,
        *,
        release_id: str,
        nonce: str,
        rung: str,
        contract_sha256: str,
        grok_release_id: str,
        require_success: bool,
        allow_pending: bool = False,
    ) -> list[str]:
        root = self.layout.rung_transcript_root
        release_root = root / release_id
        run_root = self.layout.rung_transcript_dir(release_id, nonce)
        _verify_dir(root, 0o755, self.layout.root_uid, self.layout.root_gid)
        _verify_dir(release_root, 0o755, self.layout.root_uid, self.layout.root_gid)
        _verify_dir(run_root, 0o755, self.layout.root_uid, self.layout.root_gid)
        pending = self._pending_rung_executions(
            release_id=release_id,
            nonce=nonce,
            rung=rung,
            contract_sha256=contract_sha256,
            grok_release_id=grok_release_id,
        )
        if pending and not allow_pending:
            raise ReleaseError("rung canary has a pending execution")
        digests: list[str] = []
        failed = False
        for path in sorted(run_root.iterdir(), key=lambda item: item.name):
            if PENDING_RUN_RE.fullmatch(path.name) is not None:
                continue
            if path.name in {
                "pending-qualification-real-pair.json",
                "real-pair.json",
            }:
                continue
            if not path.name.endswith(".json"):
                raise ReleaseError("rung transcript directory contains an unknown entry")
            digest = path.name[:-5]
            if RELEASE_ID_RE.fullmatch(digest) is None:
                raise ReleaseError("rung transcript filename is invalid")
            raw, _mode = _read_regular(
                path,
                uid=self.layout.root_uid,
                gid=self.layout.root_gid,
                mode=0o444,
                maximum=65_536,
            )
            if _sha256_bytes(raw) != digest:
                raise ReleaseError("rung execution transcript digest changed")
            try:
                value = json.loads(raw)
            except (UnicodeDecodeError, ValueError) as exc:
                raise ReleaseError(f"cannot parse rung execution transcript: {exc}") from exc
            transcript = self._validate_rung_transcript_value(
                value,
                release_id=release_id,
                nonce=nonce,
                rung=rung,
                contract_sha256=contract_sha256,
                grok_release_id=grok_release_id,
                expected_digest=digest,
            )
            failed = failed or transcript["returncode"] != 0
            digests.append(digest)
        if len(digests) > 64:
            raise ReleaseError("rung canary execution transcript set exceeds its bound")
        if require_success and (not digests or failed):
            raise ReleaseError("rung canary lacks an exact all-success execution set")
        return digests

    def _pending_rung_executions(
        self,
        *,
        release_id: str,
        nonce: str,
        rung: str,
        contract_sha256: str,
        grok_release_id: str,
    ) -> list[tuple[dict[str, object], Path]]:
        run_root = self.layout.rung_transcript_dir(release_id, nonce)
        _verify_dir(run_root, 0o755, self.layout.root_uid, self.layout.root_gid)
        pending_json: dict[str, Path] = {}
        for path in run_root.iterdir():
            match = PENDING_RUN_RE.fullmatch(path.name)
            if match is None:
                continue
            run_id = match.group(1)
            if run_id in pending_json:
                raise ReleaseError("duplicate rung pending execution artifact")
            pending_json[run_id] = path

        fields = {
            "schema_version",
            "transcript_kind",
            "release_id",
            "host_id",
            "rung",
            "contract_sha256",
            "grok_release_id",
            "canary_nonce",
            "run_id",
            "argv_sha256",
            "started_unix_ns",
        }
        records: list[tuple[dict[str, object], Path]] = []
        for run_id in sorted(pending_json):
            path = pending_json[run_id]
            value = self._read_json(
                path,
                uid=self.layout.root_uid,
                gid=self.layout.root_gid,
                mode=0o444,
            )
            if (
                set(value) != fields
                or value.get("schema_version") != RUNG_TRANSCRIPT_SCHEMA_VERSION
                or value.get("transcript_kind") != "manual"
                or value.get("release_id") != release_id
                or value.get("host_id") != self._host_id()
                or value.get("rung") != rung
                or value.get("contract_sha256") != contract_sha256
                or value.get("grok_release_id") != grok_release_id
                or value.get("canary_nonce") != nonce
                or value.get("run_id") != run_id
                or type(value.get("argv_sha256")) is not str
                or RELEASE_ID_RE.fullmatch(str(value.get("argv_sha256"))) is None
                or type(value.get("started_unix_ns")) is not int
                or value.get("started_unix_ns", 0) <= 0
            ):
                raise ReleaseError("pending rung execution intent is invalid or mismatched")
            records.append((value, path))
        return records

    def _pending_record_is_active(self, path: Path, *, recovery: bool = False) -> bool:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        acquired = False
        try:
            info = os.fstat(descriptor)
            actual_mode = stat.S_IMODE(info.st_mode)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != self.layout.root_uid
                or info.st_gid != self.layout.root_gid
                or (
                    recovery
                    and (
                        actual_mode not in {0o600, 0o444}
                        or not 0 <= info.st_size <= 65_536
                    )
                )
                or (
                    not recovery
                    and (actual_mode != 0o444 or not 1 <= info.st_size <= 65_536)
                )
            ):
                raise ReleaseError("pending rung execution record changed identity")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
                return False
            except BlockingIOError:
                return True
        finally:
            if acquired:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _create_pending_record(self, path: Path, value: object) -> int:
        _verify_dir(path.parent, 0o755, self.layout.root_uid, self.layout.root_gid)
        data = _canonical_json(value) + b"\n"
        if len(data) > 65_536:
            raise ReleaseError("pending rung execution record exceeds its bound")
        flags = (
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(path, flags, 0o600)
        except OSError as exc:
            raise ReleaseError(f"cannot create rung execution record: {exc}") from exc
        try:
            os.fchown(descriptor, self.layout.root_uid, self.layout.root_gid)
            # Hold the liveness lock before the first fallible content write.
            # If this process is killed at any later construction stage, the
            # kernel releases the lock and explicit abort can safely reconcile
            # the exact-pattern partial record.
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            _write_all(descriptor, data, path)
            os.fchmod(descriptor, 0o444)
            os.fsync(descriptor)
            _fsync_dir(path.parent)
            return descriptor
        except BaseException:
            os.close(descriptor)
            try:
                path.unlink()
                _fsync_dir(path.parent)
            except FileNotFoundError:
                pass
            raise

    def _validate_rung_evidence_value(
        self,
        release_id: str,
        value: object,
        *,
        expected_digest: str | None = None,
    ) -> dict[str, str]:
        fields = {
            "schema_version", "release_id", "host_id", "rung", "route_profile",
            "contract_sha256", "grok_release_id", "model_id", "measured_unix_ns",
            "canary_nonce", "release_qualification_sha256",
            "real_pair_result_sha256", "measurements", "overall_pass",
        }
        if not isinstance(value, dict) or set(value) != fields:
            raise ReleaseError("rung evidence has an unexpected shape")
        rung = value.get("rung")
        route_profile = value.get("route_profile")
        contract = value.get("contract_sha256")
        grok_release = value.get("grok_release_id")
        model_id = value.get("model_id")
        measurements = value.get("measurements")
        nonce = value.get("canary_nonce")
        if (
            value.get("schema_version") != RUNG_EVIDENCE_SCHEMA_VERSION
            or value.get("release_id") != release_id
            or value.get("host_id") != self._host_id()
            or type(rung) is not str
            or RUNG_TOKEN_RE.fullmatch(rung) is None
            or not _route_profile_matches_rung(route_profile, rung)
            or type(contract) is not str
            or RELEASE_ID_RE.fullmatch(contract) is None
            or type(grok_release) is not str
            or GROK_RELEASE_RE.fullmatch(grok_release) is None
            or type(model_id) is not str
            or MODEL_ID_RE.fullmatch(model_id) is None
            or type(value.get("measured_unix_ns")) is not int
            or value.get("measured_unix_ns", 0) <= 0
            or not isinstance(measurements, dict)
            or set(measurements) != RUNG_MEASUREMENT_FIELDS
            or any(
                measurements.get(field) is not True
                for field in RUNG_MEASUREMENT_FIELDS
                if field not in {"duration_ms", "result_sha256"}
            )
            or type(measurements.get("duration_ms")) is not int
            or not 1 <= measurements.get("duration_ms", 0) <= 86_400_000
            or type(measurements.get("result_sha256")) is not str
            or RELEASE_ID_RE.fullmatch(str(measurements.get("result_sha256"))) is None
            or value.get("overall_pass") is not True
            or type(nonce) is not str
            or RELEASE_ID_RE.fullmatch(str(nonce)) is None
            or type(value.get("release_qualification_sha256")) is not str
            or RELEASE_ID_RE.fullmatch(
                str(value.get("release_qualification_sha256"))
            ) is None
            or type(value.get("real_pair_result_sha256")) is not str
            or RELEASE_ID_RE.fullmatch(
                str(value.get("real_pair_result_sha256"))
            ) is None
        ):
            raise ReleaseError("rung evidence does not bind a complete passing measurement")
        assert isinstance(nonce, str)
        release_state, release_digest = self._validate_release_qualification(release_id)
        real_canary = {
            "release_id": release_id,
            "canary_nonce": nonce,
            "canary_kind": "rung",
            "rung": rung,
            "route_profile": route_profile,
            "contract_sha256": contract,
            "grok_release_id": grok_release,
            "model_id": model_id,
        }
        run_root = self.layout.rung_transcript_dir(release_id, nonce)
        _verify_dir(run_root, 0o755, self.layout.root_uid, self.layout.root_gid)
        entries = sorted(path.name for path in run_root.iterdir())
        if (
            "real-pair.json" not in entries
            or len(entries) > 65
            or any(
                name != "real-pair.json"
                and re.fullmatch(r"[0-9a-f]{64}\.json", name) is None
                for name in entries
            )
        ):
            raise ReleaseError("rung qualification result set contains residue")
        self._rung_transcript_digests(
            release_id=release_id,
            nonce=nonce,
            rung=str(rung),
            contract_sha256=str(contract),
            grok_release_id=str(grok_release),
            require_success=False,
        )
        real_result, real_digest = self._read_qualification_result(
            self.layout.rung_qualification_path(release_id, nonce),
            step="real-pair",
            canary=real_canary,
        )
        derived_result = _sha256_bytes(
            _canonical_json(
                {
                    "release_qualification_sha256": release_digest,
                    "real_pair_result_sha256": real_digest,
                }
            )
            + b"\n"
        )
        load_result, _ = self._read_qualification_result(
            self.layout.qualification_result_path(release_id, "load32"),
            step="load32",
            canary={
                "release_id": release_id,
                "canary_nonce": release_state["canary_nonce"],
                "canary_kind": "release",
                "rung": "direct",
                "route_profile": "direct",
                "contract_sha256": None,
                "grok_release_id": release_state["grok_release_id"],
                "model_id": release_state["model_id"],
            },
        )
        fault_result, _ = self._read_qualification_result(
            self.layout.qualification_result_path(release_id, "fault-recovery"),
            step="fault-recovery",
            canary={
                "release_id": release_id,
                "canary_nonce": release_state["canary_nonce"],
                "canary_kind": "release",
                "rung": "direct",
                "route_profile": "direct",
                "contract_sha256": None,
                "grok_release_id": release_state["grok_release_id"],
                "model_id": release_state["model_id"],
            },
        )
        expected_measurements = {
            "duration_ms": max(
                1,
                int(load_result["duration_ms"])
                + int(fault_result["duration_ms"])
                + int(real_result["duration_ms"]),
            ),
            "fault_load_canary_verified": True,
            "host_limits_verified": True,
            "result_sha256": derived_result,
            "post_repair_reconnect_cache_execution_units_verified": True,
            "shared_route": True,
            "teardown_clean": True,
            "transport_timing_verified": True,
            "two_sessions": True,
        }
        if (
            value.get("release_qualification_sha256") != release_digest
            or value.get("real_pair_result_sha256") != real_digest
            or measurements != expected_measurements
        ):
            raise ReleaseError("rung evidence does not match fixed qualification results")
        if expected_digest is None:
            expected_digest = _sha256_bytes(_canonical_json(value) + b"\n")
        if RELEASE_ID_RE.fullmatch(expected_digest) is None:
            raise ReleaseError("rung evidence digest is invalid")
        assert isinstance(rung, str) and isinstance(contract, str)
        assert isinstance(grok_release, str)
        return {
            "contract_sha256": contract,
            "evidence_sha256": expected_digest,
            "grok_release_id": grok_release,
            "rung": rung,
        }

    def _validate_qualified_rungs(
        self,
        release_id: str,
        records: Iterable[Mapping[str, object]],
    ) -> list[dict[str, str]]:
        normalized = self._normalize_qualified_rungs(records)
        root = self.layout.rung_evidence_root
        _verify_dir(root, 0o755, self.layout.root_uid, self.layout.root_gid)
        if normalized:
            _verify_dir(
                root / release_id,
                0o755,
                self.layout.root_uid,
                self.layout.root_gid,
            )
        for record in normalized:
            digest = record["evidence_sha256"]
            raw, _mode = _read_regular(
                root / release_id / f"{digest}.json",
                uid=self.layout.root_uid,
                gid=self.layout.root_gid,
                mode=0o444,
                maximum=1024 * 1024,
            )
            if _sha256_bytes(raw) != digest:
                raise ReleaseError("qualified rung evidence digest changed")
            try:
                value = json.loads(raw)
            except (UnicodeDecodeError, ValueError) as exc:
                raise ReleaseError(f"cannot parse qualified rung evidence: {exc}") from exc
            if self._validate_rung_evidence_value(
                release_id,
                value,
                expected_digest=digest,
            ) != record:
                raise ReleaseError("qualified rung selection/evidence mismatch")
        return normalized

    def _deny_record(self) -> dict[str, object] | None:
        if not _present(self.layout.rollback_deny):
            return None
        return self._read_json(
            self.layout.rollback_deny,
            uid=self.layout.root_uid,
            gid=self.layout.root_gid,
            mode=0o444,
        )

    def _publish_deny(self, operation: str, from_release: str | None, to_release: str) -> None:
        if operation not in {"install", "rollback", "canary"}:
            raise ReleaseError(f"unsupported deny operation: {operation}")
        if RELEASE_ID_RE.fullmatch(to_release) is None:
            raise ReleaseError("deny target release is invalid")
        if from_release is not None and RELEASE_ID_RE.fullmatch(from_release) is None:
            raise ReleaseError("deny source release is invalid")
        record = {
            "schema_version": CONTROL_SCHEMA_VERSION,
            "operation": operation,
            "from_release": from_release,
            "to_release": to_release,
        }
        existing = self._deny_record()
        if existing is not None:
            if (
                set(existing)
                != {"schema_version", "operation", "from_release", "to_release"}
                or
                existing.get("schema_version") != CONTROL_SCHEMA_VERSION
                or existing.get("operation") != operation
                or existing.get("from_release") != from_release
                or existing.get("to_release") != to_release
                or not (
                    existing.get("from_release") is None
                    or RELEASE_ID_RE.fullmatch(str(existing.get("from_release")))
                )
            ):
                raise ReleaseError("a different interrupted release operation is fenced")
            return
        _atomic_json(
            self.layout.rollback_deny,
            record,
            mode=0o444,
            uid=self.layout.root_uid,
            gid=self.layout.root_gid,
            parent_mode=0o755,
        )

    def _clear_deny(self) -> None:
        if not _present(self.layout.rollback_deny):
            return
        _read_regular(
            self.layout.rollback_deny,
            uid=self.layout.root_uid,
            gid=self.layout.root_gid,
            mode=0o444,
            maximum=1024 * 1024,
        )
        self.layout.rollback_deny.unlink()
        _fsync_dir(self.layout.root_control)

    @staticmethod
    def _host_id() -> str:
        """Return a stable non-secret digest for the installed host identity."""

        try:
            raw = Path("/etc/machine-id").read_text(encoding="ascii").strip()
        except OSError as exc:
            raise ReleaseError(f"cannot read host identity: {exc}") from exc
        if re.fullmatch(r"[0-9a-f]{32}", raw) is None:
            raise ReleaseError("host machine identity is invalid")
        return hashlib.sha256(raw.encode("ascii")).hexdigest()

    @staticmethod
    def _boot_id() -> str:
        try:
            value = Path("/proc/sys/kernel/random/boot_id").read_text(
                encoding="ascii"
            ).strip()
        except OSError as exc:
            raise ReleaseError(f"cannot read boot identity: {exc}") from exc
        if re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            value,
        ) is None:
            raise ReleaseError("kernel boot identity is invalid")
        return value

    def _write_boot_inventory(self, release_id: str, snapshot: object) -> str:
        if RELEASE_ID_RE.fullmatch(release_id) is None:
            raise ReleaseError("boot inventory release ID is invalid")
        record = {
            "schema_version": BOOT_INVENTORY_SCHEMA_VERSION,
            "release_id": release_id,
            "host_id": self._host_id(),
            "boot_id": self._boot_id(),
            "checked_unix_ns": time.time_ns(),
            "inventory_sha256": _sha256_bytes(_canonical_json(snapshot)),
        }
        path = self.layout.boot_inventory_path(release_id)
        _atomic_json(
            path,
            record,
            mode=0o444,
            uid=self.layout.root_uid,
            gid=self.layout.root_gid,
            parent_mode=0o755,
        )
        return _sha256_bytes(_canonical_json(record) + b"\n")

    def _validate_boot_inventory(self, release_id: str) -> dict[str, object]:
        value = self._read_json(
            self.layout.boot_inventory_path(release_id),
            uid=self.layout.root_uid,
            gid=self.layout.root_gid,
            mode=0o444,
        )
        if (
            set(value)
            != {
                "schema_version", "release_id", "host_id", "boot_id",
                "checked_unix_ns", "inventory_sha256",
            }
            or value.get("schema_version") != BOOT_INVENTORY_SCHEMA_VERSION
            or value.get("release_id") != release_id
            or value.get("host_id") != self._host_id()
            or value.get("boot_id") != self._boot_id()
            or type(value.get("checked_unix_ns")) is not int
            or value.get("checked_unix_ns", 0) <= 0
            or type(value.get("inventory_sha256")) is not str
            or RELEASE_ID_RE.fullmatch(str(value.get("inventory_sha256"))) is None
        ):
            raise ReleaseError("current-boot inventory evidence is invalid")
        return value

    @staticmethod
    def _criterion(
        criterion_id: str,
        passed: bool,
        result: object,
        duration_ms: int = 0,
    ) -> dict[str, object]:
        if criterion_id not in EVIDENCE_CRITERIA:
            raise ReleaseError(f"unknown promotion criterion: {criterion_id}")
        if type(passed) is not bool or type(duration_ms) is not int:
            raise ReleaseError("promotion criterion types are invalid")
        if not 0 <= duration_ms <= 300_000:
            raise ReleaseError("promotion criterion duration is invalid")
        return {
            "id": criterion_id,
            "passed": passed,
            "result_sha256": _sha256_bytes(_canonical_json(result)),
            "duration_ms": duration_ms,
        }

    def _read_runner_scope_record(self, path: Path) -> dict[str, object]:
        match = RUNNER_SCOPE_RECORD_RE.fullmatch(path.name)
        if match is None:
            raise ReleaseError(f"unexpected installer runner scope entry: {path}")
        raw, _mode = _read_regular(
            path,
            uid=self.layout.root_uid,
            gid=self.layout.root_gid,
            mode=0o600,
            maximum=16_384,
        )
        try:
            value = json.loads(raw)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ReleaseError("installer runner scope record is invalid JSON") from exc
        fields = {
            "schema_version",
            "record_version",
            "run_id",
            "runner_kind",
            "release_id",
            "phase",
            "owner_pid",
            "owner_start_ticks",
            "owner_boot_id",
            "parent_path",
            "parent_device",
            "parent_inode",
            "scope_path",
            "scope_device",
            "scope_inode",
            "target_uid",
            "target_gid",
        }
        if type(value) is not dict or set(value) != fields:
            raise ReleaseError("installer runner scope record has an invalid schema")
        phase = value.get("phase")
        record_version = value.get("record_version")
        scope_path = Path(str(value.get("scope_path")))
        parent_path = Path(str(value.get("parent_path")))
        # Reader-only compatibility for journals emitted by the withdrawn
        # manual-canary runner experiment; new scopes cannot use this kind.
        readable_runner_kinds = {"gate-smoke", "qualification", "manual-canary"}
        if (
            value.get("schema_version") != SCHEMA_VERSION
            or type(record_version) is not int
            or record_version not in {1, RUNNER_SCOPE_RECORD_VERSION}
            or value.get("run_id") != match.group(1)
            or value.get("runner_kind")
            not in readable_runner_kinds
            or (
                value.get("release_id") is not None
                and (
                    type(value.get("release_id")) is not str
                    or RELEASE_ID_RE.fullmatch(str(value["release_id"])) is None
                )
            )
            or (
                record_version == 1
                and phase
                not in {"PREPARED", "CREATED_ROOT", "DELEGATED", "RUNNING"}
            )
            or (
                record_version == RUNNER_SCOPE_RECORD_VERSION
                and phase
                not in {
                    "PREPARED",
                    "CREATED_ROOT",
                    "DELEGATING",
                    "DELEGATED",
                    "RUNNING",
                    "RECOVERED",
                    "CONTAINED",
                }
            )
            or type(value.get("owner_pid")) is not int
            or not 1 <= int(value["owner_pid"]) < 2**31
            or type(value.get("owner_start_ticks")) is not int
            or not 1 <= int(value["owner_start_ticks"]) < 2**63
            or type(value.get("owner_boot_id")) is not str
            or re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                str(value["owner_boot_id"]),
            )
            is None
            or not parent_path.is_absolute()
            or scope_path.parent != parent_path
            or scope_path.name != f"grok-installer-{match.group(1)}"
            or RUNNER_SCOPE_NAME_RE.fullmatch(scope_path.name) is None
            or any(
                type(value.get(name)) is not int or int(value[name]) < 0
                for name in (
                    "parent_device",
                    "parent_inode",
                    "target_uid",
                    "target_gid",
                )
            )
            or (
                phase == "PREPARED"
                and (
                    value.get("scope_device") is not None
                    or value.get("scope_inode") is not None
                )
            )
            or (
                phase
                in {
                    "CREATED_ROOT",
                    "DELEGATING",
                    "DELEGATED",
                    "RUNNING",
                    "RECOVERED",
                    "CONTAINED",
                }
                and (
                    type(value.get("scope_device")) is not int
                    or int(value["scope_device"]) < 1
                    or type(value.get("scope_inode")) is not int
                    or int(value["scope_inode"]) < 1
                )
            )
            or (
                value.get("target_uid"),
                value.get("target_gid"),
            )
            not in {
                (self.layout.target_uid, self.layout.target_gid),
                (self.layout.root_uid, self.layout.root_gid),
            }
        ):
            raise ReleaseError("installer runner scope authority is invalid")
        try:
            parent_path.relative_to(Path("/sys/fs/cgroup"))
        except ValueError as exc:
            raise ReleaseError("installer runner scope escapes cgroup-v2") from exc
        return value

    def _runner_owner_can_execute(self, record: Mapping[str, object]) -> bool:
        """Return whether the exact journal owner can still execute code."""

        pid = int(record["owner_pid"])
        if record.get("owner_boot_id") != self._boot_id():
            return False
        try:
            descriptor = os.pidfd_open(pid, 0)
        except ProcessLookupError:
            return False
        except OSError as exc:
            raise SessionContainmentError(
                "cannot anchor installer runner owner identity"
            ) from exc
        try:
            raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
            close = raw.rfind(")")
            fields = raw[close + 2 :].split() if close >= 0 else []
            if (
                len(fields) < 20
                or fields[0] in {"Z", "X"}
                or not fields[19].isdecimal()
                or int(fields[19]) != record["owner_start_ticks"]
            ):
                return False
            with selectors.DefaultSelector() as selector:
                selector.register(descriptor, selectors.EVENT_READ)
                return not bool(selector.select(0))
        except (FileNotFoundError, ProcessLookupError):
            return False
        except (OSError, UnicodeError) as exc:
            raise SessionContainmentError(
                "cannot verify installer runner owner identity"
            ) from exc
        finally:
            os.close(descriptor)

    def _delete_runner_scope_record(
        self, path: Path, expected: Mapping[str, object]
    ) -> None:
        raw, _mode = _read_regular(
            path,
            uid=self.layout.root_uid,
            gid=self.layout.root_gid,
            mode=0o600,
            maximum=16_384,
        )
        if raw != _canonical_json(expected) + b"\n":
            raise SessionContainmentError(
                "installer runner scope record changed before deletion"
            )
        path.unlink()
        _fsync_dir(path.parent)

    def _discard_runner_scope_stages(self) -> None:
        root = self.layout.runner_scope_root
        changed = False
        for path in tuple(root.iterdir()):
            match = RUNNER_SCOPE_TEMP_RE.fullmatch(path.name)
            if match is None:
                continue
            info = path.lstat()
            if (
                path.is_symlink()
                or not stat.S_ISREG(info.st_mode)
                or info.st_uid != self.layout.root_uid
                or info.st_gid != self.layout.root_gid
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink not in {1, 2}
            ):
                raise SessionContainmentError(
                    "installer runner journal contains an unsafe stage"
                )
            if info.st_nlink == 2:
                final = root / match.group("target")
                final_info = final.lstat()
                if (
                    final.is_symlink()
                    or not stat.S_ISREG(final_info.st_mode)
                    or final_info.st_uid != self.layout.root_uid
                    or final_info.st_gid != self.layout.root_gid
                    or stat.S_IMODE(final_info.st_mode) != 0o600
                    or final_info.st_nlink != 2
                    or (final_info.st_dev, final_info.st_ino)
                    != (info.st_dev, info.st_ino)
                ):
                    raise SessionContainmentError(
                        "installer runner journal stage has no exact final link"
                    )
            current = path.lstat()
            if (current.st_dev, current.st_ino, current.st_nlink) != (
                info.st_dev,
                info.st_ino,
                info.st_nlink,
            ):
                raise SessionContainmentError(
                    "installer runner journal stage changed before removal"
                )
            path.unlink()
            changed = True
        if changed:
            _fsync_dir(root)

    def _recover_qualification_runner_runtime(
        self,
        runner: _RunnerCgroup,
        release_id: str,
        deadline_monotonic_ns: int,
        *,
        strict_direct: bool,
    ) -> bool:
        """Reconcile killed qualification descendants before removing their parent."""

        if type(strict_direct) is not bool:
            raise SessionContainmentError(
                "qualification recovery mode is not exact"
            )
        if RELEASE_ID_RE.fullmatch(release_id) is None:
            raise SessionContainmentError(
                "qualification runner has no exact release identity"
            )
        remaining_ms = (
            deadline_monotonic_ns - time.monotonic_ns() - 1_000_000_000
        ) // 1_000_000
        if remaining_ms < 100:
            raise SessionContainmentError(
                "qualification runtime recovery has no bounded cleanup reserve"
            )
        self.validate_release_pair(release_id)
        release_dir = self.layout.user_releases / release_id
        stop_ms = min(120_000, int(remaining_ms))
        helper = (
            "import sys;"
            "from pathlib import Path;"
            "release=Path(sys.argv[1]).resolve(strict=True);"
            "sys.path.insert(0,str(release));"
            "from grok_ms.supervisor import recover_offline;"
            "strict=sys.argv[4]=='1';"
            "outcome=recover_offline(sys.argv[2],release,stop_ms=int(sys.argv[3]),"
            "recover_compatibility=not strict,"
            "forbid_compatibility_handoff=strict);"
            "changed=(outcome.recovered or outcome.provider_records!=0 or "
            "outcome.child_records!=0 or outcome.probe_records!=0);"
            "raise SystemExit(3 if changed else 0)"
        )
        environment = {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": str(self.layout.user_root.parents[2]),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "GROK_MULTI_SESSION": "1",
        }
        if self.layout.test_install:
            environment.update(
                {
                    "GROK_TESTING": "1",
                    "GROK_TEST_SKIP_WARM_HANDOFF": "1",
                }
            )
        demote = self._drop_identity(
            self.layout.target_uid,
            self.layout.target_gid,
        )
        process: subprocess.Popen[bytes] | None = None
        leader_pidfd = -1
        try:
            process = subprocess.Popen(
                [
                    "/usr/bin/python3",
                    "-I",
                    "-B",
                    "-c",
                    helper,
                    str(release_dir),
                    str(self.layout.multi_control),
                    str(stop_ms),
                    "1" if strict_direct else "0",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                pass_fds=(runner.descriptor,),
                start_new_session=True,
                env=environment,
                preexec_fn=runner.recovery_preexec(demote),
            )
            leader_pidfd = os.pidfd_open(process.pid, 0)
            os.set_inheritable(leader_pidfd, False)
            returncode = _kill_session_group_before_reap(
                process,
                leader_pidfd,
                graceful_seconds=max(
                    0.0,
                    min(
                        stop_ms / 1_000,
                        (deadline_monotonic_ns - time.monotonic_ns())
                        / 1_000_000_000,
                    ),
                ),
                deadline_monotonic_ns=deadline_monotonic_ns,
            )
            if returncode not in {0, 3}:
                raise SessionContainmentError(
                    "qualification runtime recovery did not converge"
                )
            return returncode == 3
        except (OSError, subprocess.SubprocessError) as exc:
            raise SessionContainmentError(
                "cannot execute qualification runtime recovery"
            ) from exc
        finally:
            if process is not None and process.returncode is None:
                if leader_pidfd >= 0:
                    _kill_session_group_before_reap(
                        process,
                        leader_pidfd,
                        graceful_seconds=0.0,
                        deadline_monotonic_ns=deadline_monotonic_ns,
                    )
                else:
                    _kill_session_group_without_pidfd_before_reap(
                        process,
                        deadline_monotonic_ns=deadline_monotonic_ns,
                    )
            if leader_pidfd >= 0:
                os.close(leader_pidfd)

    def _runner_after_kill(
        self,
        runner: _RunnerCgroup,
        record: Mapping[str, object],
        deadline_monotonic_ns: int,
    ) -> Callable[[], bool] | None:
        if record.get("runner_kind") not in {"qualification", "manual-canary"}:
            return None
        # CREATED_ROOT/DELEGATING cannot have returned from scope creation, so
        # no unprivileged runner could have started.  In particular, do not
        # launch user recovery into a partially chowned hierarchy.
        if record.get("phase") not in {"DELEGATED", "RUNNING"}:
            return None
        release_id = record.get("release_id")
        if type(release_id) is not str:
            raise SessionContainmentError(
                "qualification runner release identity is absent"
            )
        return lambda: self._recover_qualification_runner_runtime(
            runner,
            release_id,
            deadline_monotonic_ns,
            strict_direct=record.get("runner_kind") == "qualification",
        )

    def _recover_runner_scopes(self, deadline_monotonic_ns: int) -> None:
        if not self._runner_scopes_required():
            return
        with _runner_journal_locked(
            self.layout.runner_scope_lock,
            self.layout.root_uid,
            self.layout.root_gid,
            deadline_monotonic_ns,
        ):
            self._recover_runner_scopes_locked(deadline_monotonic_ns)

    def _recover_runner_scopes_locked(self, deadline_monotonic_ns: int) -> None:
        root = self.layout.runner_scope_root
        _ensure_dir(
            root,
            0o700,
            self.layout.root_uid,
            self.layout.root_gid,
        )
        self._discard_runner_scope_stages()
        paths = sorted(root.iterdir(), key=lambda item: item.name)
        if len(paths) > MAX_SWITCH_INVENTORY_ENTRIES:
            raise SessionContainmentError(
                "installer runner scope recovery inventory limit exceeded"
            )
        for path in paths:
            if time.monotonic_ns() >= deadline_monotonic_ns:
                raise SessionContainmentError(
                    "installer runner scope recovery deadline expired"
                )
            record = self._read_runner_scope_record(path)
            if self._runner_owner_can_execute(record):
                continue
            scope = Path(str(record["scope_path"]))
            try:
                scope_info = scope.lstat()
            except FileNotFoundError:
                if record.get("phase") in {"PREPARED", "CONTAINED"}:
                    self._delete_runner_scope_record(path, record)
                    continue
                # CREATED_ROOT is intentionally conservative for journals
                # emitted before DELEGATING existed.  A missing delegated or
                # running scope likewise has no durable proof that runtime
                # recovery preceded its removal.
                raise SessionContainmentError(
                    "installer runner scope disappeared before containment proof"
                )
            parent = Path(str(record["parent_path"]))
            try:
                parent_info = parent.lstat()
            except OSError as exc:
                raise SessionContainmentError(
                    "installer runner scope parent is unavailable"
                ) from exc
            if (
                parent.is_symlink()
                or not stat.S_ISDIR(parent_info.st_mode)
                or (parent_info.st_dev, parent_info.st_ino)
                != (record["parent_device"], record["parent_inode"])
            ):
                raise SessionContainmentError(
                    "installer runner scope parent identity changed"
                )
            if (
                scope.is_symlink()
                or not stat.S_ISDIR(scope_info.st_mode)
                or scope_info.st_dev != parent_info.st_dev
            ):
                raise SessionContainmentError(
                    "installer runner cgroup identity changed"
                )
            if record["phase"] == "PREPARED":
                if (scope_info.st_uid, scope_info.st_gid) != (
                    self.layout.root_uid,
                    self.layout.root_gid,
                ):
                    raise SessionContainmentError(
                        "uncommitted installer runner cgroup is not root-owned"
                    )
                scope_info = scope.lstat()
                created = dict(record)
                created.update(
                    {
                        "phase": "CREATED_ROOT",
                        "scope_device": scope_info.st_dev,
                        "scope_inode": scope_info.st_ino,
                    }
                )
                _atomic_json(
                    path,
                    created,
                    mode=0o600,
                    uid=self.layout.root_uid,
                    gid=self.layout.root_gid,
                    parent_mode=0o700,
                )
                record = created
            flags = (
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(scope, flags)
            runner = _RunnerCgroup(
                record_path=path,
                record=record,
                descriptor=descriptor,
                root_uid=self.layout.root_uid,
                root_gid=self.layout.root_gid,
                journal_lock_path=self.layout.runner_scope_lock,
                journal_deadline_monotonic_ns=deadline_monotonic_ns,
            )
            try:
                if (
                    scope.is_symlink()
                    or not stat.S_ISDIR(scope_info.st_mode)
                    or (scope_info.st_dev, scope_info.st_ino)
                    != (record["scope_device"], record["scope_inode"])
                ):
                    raise SessionContainmentError(
                        "installer runner cgroup identity changed"
                    )
                runner.cleanup(
                    deadline_monotonic_ns,
                    after_kill=self._runner_after_kill(
                        runner,
                        record,
                        deadline_monotonic_ns,
                    ),
                    journal_locked=True,
                )
                runner.finalize_record(journal_locked=True)
            finally:
                runner.close()

    def _create_runner_scope(
        self,
        uid: int,
        gid: int,
        deadline_monotonic_ns: int,
        *,
        runner_kind: str,
        release_id: str | None,
    ) -> _RunnerCgroup:
        if not self._runner_scopes_required():
            raise ReleaseError(
                "installer runner scopes require the fixed live root layout"
            )
        if runner_kind not in {
            "gate-smoke",
            "qualification",
        }:
            raise ReleaseError("installer runner kind is invalid")
        if release_id is not None and RELEASE_ID_RE.fullmatch(release_id) is None:
            raise ReleaseError("installer runner release ID is invalid")
        self._recover_runner_scopes(deadline_monotonic_ns)
        placement = _runner_cgroup_parent(
            self.layout.target_uid,
            self.layout.target_gid,
        )
        parent = placement.parent
        parent_info = placement.parent_info
        root = self.layout.runner_scope_root
        nonce = secrets.token_hex(12)
        scope = parent / f"grok-installer-{nonce}"
        record_path = root / f"{nonce}.json"
        prepared: dict[str, object] = {
            "schema_version": SCHEMA_VERSION,
            "record_version": RUNNER_SCOPE_RECORD_VERSION,
            "run_id": nonce,
            "runner_kind": runner_kind,
            "release_id": release_id,
            "phase": "PREPARED",
            "owner_pid": os.getpid(),
            "owner_start_ticks": self._proc_start_ticks(os.getpid()),
            "owner_boot_id": self._boot_id(),
            "parent_path": str(parent),
            "parent_device": parent_info.st_dev,
            "parent_inode": parent_info.st_ino,
            "scope_path": str(scope),
            "scope_device": None,
            "scope_inode": None,
            "target_uid": uid,
            "target_gid": gid,
        }
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        parent_descriptor = os.open(parent, flags)
        anchored_parent = os.fstat(parent_descriptor)
        try:
            anchored_delegate = os.getxattr(
                parent_descriptor,
                "user.delegate",
            )
        except OSError as exc:
            closing_parent = parent_descriptor
            parent_descriptor = -1
            os.close(closing_parent)
            raise SessionContainmentError(
                "installer runner delegated parent lost its delegation marker"
            ) from exc
        if (
            not stat.S_ISDIR(anchored_parent.st_mode)
            or (anchored_parent.st_dev, anchored_parent.st_ino)
            != (parent_info.st_dev, parent_info.st_ino)
            or anchored_delegate != b"1"
        ):
            closing_parent = parent_descriptor
            parent_descriptor = -1
            os.close(closing_parent)
            raise SessionContainmentError(
                "installer runner delegated parent changed identity"
            )
        try:
            with _runner_journal_locked(
                self.layout.runner_scope_lock,
                self.layout.root_uid,
                self.layout.root_gid,
                deadline_monotonic_ns,
            ):
                _exclusive_runner_record(
                    record_path,
                    prepared,
                    uid=self.layout.root_uid,
                    gid=self.layout.root_gid,
                )
        except BaseException:
            closing_parent = parent_descriptor
            parent_descriptor = -1
            os.close(closing_parent)
            raise
        descriptor = -1
        current_record = prepared
        try:
            os.mkdir(
                scope.name,
                mode=0o700,
                dir_fd=parent_descriptor,
            )
            descriptor = os.open(scope.name, flags, dir_fd=parent_descriptor)
            info = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_dev != parent_info.st_dev
                or (info.st_uid, info.st_gid)
                != (self.layout.root_uid, self.layout.root_gid)
            ):
                raise SessionContainmentError(
                    "created installer runner cgroup has an unsafe identity"
                )
            created = dict(prepared)
            created.update(
                {
                    "phase": "CREATED_ROOT",
                    "scope_device": info.st_dev,
                    "scope_inode": info.st_ino,
                }
            )
            with _runner_journal_locked(
                self.layout.runner_scope_lock,
                self.layout.root_uid,
                self.layout.root_gid,
                deadline_monotonic_ns,
            ):
                _atomic_json(
                    record_path,
                    created,
                    mode=0o600,
                    uid=self.layout.root_uid,
                    gid=self.layout.root_gid,
                    parent_mode=0o700,
                )
            current_record = created
            for control in RUNNER_CGROUP_LIMIT_WRITE_ORDER:
                if control not in placement.effective_limits:
                    continue
                expected = placement.effective_limits[control]
                _runner_cgroup_write_at(
                    descriptor,
                    control,
                    (expected + "\n").encode("ascii"),
                )
                try:
                    actual = (
                        _runner_cgroup_read_at(descriptor, control, 128)
                        .decode("ascii")
                        .strip()
                    )
                except UnicodeError as exc:
                    raise SessionContainmentError(
                        f"installer runner {control} is non-ASCII"
                    ) from exc
                if actual != expected:
                    raise SessionContainmentError(
                        f"installer runner {control} did not retain the caller's effective limit"
                    )
            # Publish the delegation intent before the first ownership change.
            # Recovery therefore treats every partial chown as potentially
            # user-controlled even if the final DELEGATED state was never
            # reached.
            delegating = dict(created)
            delegating["phase"] = "DELEGATING"
            with _runner_journal_locked(
                self.layout.runner_scope_lock,
                self.layout.root_uid,
                self.layout.root_gid,
                deadline_monotonic_ns,
            ):
                _atomic_json(
                    record_path,
                    delegating,
                    mode=0o600,
                    uid=self.layout.root_uid,
                    gid=self.layout.root_gid,
                    parent_mode=0o700,
                )
            current_record = delegating
            os.chown(
                scope.name,
                uid,
                gid,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            for control in (
                "cgroup.procs",
                "cgroup.threads",
                "cgroup.subtree_control",
            ):
                try:
                    os.chown(
                        control,
                        uid,
                        gid,
                        dir_fd=descriptor,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    if control != "cgroup.threads":
                        raise
            delegated_info = os.fstat(descriptor)
            if (
                (delegated_info.st_dev, delegated_info.st_ino)
                != (created["scope_device"], created["scope_inode"])
                or (delegated_info.st_uid, delegated_info.st_gid) != (uid, gid)
            ):
                raise SessionContainmentError(
                    "delegated installer runner cgroup changed identity"
                )
            delegated = dict(delegating)
            delegated["phase"] = "DELEGATED"
            with _runner_journal_locked(
                self.layout.runner_scope_lock,
                self.layout.root_uid,
                self.layout.root_gid,
                deadline_monotonic_ns,
            ):
                _atomic_json(
                    record_path,
                    delegated,
                    mode=0o600,
                    uid=self.layout.root_uid,
                    gid=self.layout.root_gid,
                    parent_mode=0o700,
                )
            current_record = delegated
            closing_parent = parent_descriptor
            parent_descriptor = -1
            os.close(closing_parent)
            return _RunnerCgroup(
                record_path=record_path,
                record=delegated,
                descriptor=descriptor,
                root_uid=self.layout.root_uid,
                root_gid=self.layout.root_gid,
                source_cpu_affinity=placement.source_cpu_affinity,
                journal_lock_path=self.layout.runner_scope_lock,
                journal_deadline_monotonic_ns=deadline_monotonic_ns,
            )
        except BaseException as exc:
            cleanup_error: BaseException | None = None
            contained_cleanup = False
            if (
                descriptor >= 0
                and current_record.get("phase")
                in {"CREATED_ROOT", "DELEGATING", "DELEGATED"}
            ):
                # No runner child has been spawned yet, but delegation may be
                # partial.  Use the same two-kill/revocation protocol and
                # durable CONTAINED witness instead of bypassing it with a
                # direct rmdir.
                failed_runner = _RunnerCgroup(
                    record_path=record_path,
                    record=current_record,
                    descriptor=descriptor,
                    root_uid=self.layout.root_uid,
                    root_gid=self.layout.root_gid,
                    journal_lock_path=self.layout.runner_scope_lock,
                    journal_deadline_monotonic_ns=deadline_monotonic_ns,
                )
                try:
                    failed_runner.cleanup(deadline_monotonic_ns)
                    failed_runner.finalize_record()
                    contained_cleanup = True
                except BaseException as cleanup_exc:
                    cleanup_error = cleanup_exc
                finally:
                    failed_runner.close()
                    descriptor = -1
            elif descriptor >= 0:
                try:
                    _runner_cgroup_write_at(descriptor, "cgroup.kill", b"1\n")
                except BaseException as cleanup_exc:
                    cleanup_error = cleanup_exc
                try:
                    os.close(descriptor)
                except OSError as cleanup_exc:
                    cleanup_error = cleanup_error or cleanup_exc
                descriptor = -1
            if not contained_cleanup and cleanup_error is None:
                try:
                    if parent_descriptor >= 0:
                        os.rmdir(scope.name, dir_fd=parent_descriptor)
                    else:
                        scope.rmdir()
                except FileNotFoundError:
                    pass
                except OSError as cleanup_exc:
                    cleanup_error = cleanup_error or cleanup_exc
            if parent_descriptor >= 0:
                try:
                    closing_parent = parent_descriptor
                    parent_descriptor = -1
                    os.close(closing_parent)
                except OSError as cleanup_exc:
                    cleanup_error = cleanup_error or cleanup_exc
            if (
                not contained_cleanup
                and cleanup_error is None
                and not _present(scope)
            ):
                try:
                    with _runner_journal_locked(
                        self.layout.runner_scope_lock,
                        self.layout.root_uid,
                        self.layout.root_gid,
                        deadline_monotonic_ns,
                    ):
                        self._delete_runner_scope_record(
                            record_path,
                            current_record,
                        )
                except BaseException as cleanup_exc:
                    cleanup_error = cleanup_error or cleanup_exc
            if cleanup_error is not None:
                raise SessionContainmentError(
                    "installer runner cgroup creation cleanup is uncertain"
                ) from cleanup_error
            raise exc

    def _drop_identity(self, uid: int, gid: int):
        if uid == os.geteuid() and gid == os.getegid():
            return None
        if os.geteuid() != 0:
            raise ReleaseError("cannot execute canary as the selected target identity")

        def demote() -> None:
            os.setgroups([])
            os.setgid(gid)
            os.setuid(uid)

        return demote

    @staticmethod
    def _parent_death_preexec(demote):
        """Bind a non-cgroup runner to its exact installer parent."""

        owner_pid = os.getpid()

        def prepare() -> None:
            if demote is not None:
                demote()
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
                os._exit(126)
            if os.getppid() != owner_pid:
                os._exit(126)

        return prepare

    @contextmanager
    def _legacy_singleton_locked(self):
        """Hold the stable compatibility lock across installer migration."""

        parent = self.layout.user_root.parents[2] / "grok-proxy"
        parent_info = _lstat(parent)
        if parent_info is None:
            # A fresh account with no compatibility tree has no legacy lock
            # identity or legacy shell capable of recreating that tree.
            yield
            return
        directory_flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        file_flags = (
            os.O_RDWR
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        parent_fd = os.open(parent, directory_flags)
        lock_fd = -1
        locked = False
        created = False
        try:
            opened_parent = os.fstat(parent_fd)
            if (
                not stat.S_ISDIR(opened_parent.st_mode)
                or opened_parent.st_uid != self.layout.target_uid
                or opened_parent.st_gid != self.layout.target_gid
                or stat.S_IMODE(opened_parent.st_mode) & 0o002
                or (opened_parent.st_dev, opened_parent.st_ino)
                != (parent_info.st_dev, parent_info.st_ino)
            ):
                raise ReleaseError("unsafe legacy singleton lock parent")
            try:
                lock_fd = os.open(".grok-remote.lock", file_flags, dir_fd=parent_fd)
            except FileNotFoundError:
                try:
                    lock_fd = os.open(
                        ".grok-remote.lock",
                        file_flags | os.O_CREAT | os.O_EXCL,
                        0o600,
                        dir_fd=parent_fd,
                    )
                    created = True
                    os.fchown(
                        lock_fd,
                        self.layout.target_uid,
                        self.layout.target_gid,
                    )
                except FileExistsError:
                    lock_fd = os.open(
                        ".grok-remote.lock", file_flags, dir_fd=parent_fd
                    )

            info = os.fstat(lock_fd)
            allowed_modes = {0o600, 0o640, 0o644, 0o660, 0o664}
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != self.layout.target_uid
                or info.st_gid != self.layout.target_gid
                or stat.S_IMODE(info.st_mode) not in allowed_modes
                or stat.S_IMODE(info.st_mode) & 0o113
                or info.st_size != 0
                or info.st_nlink != 1
                or info.st_dev != opened_parent.st_dev
            ):
                raise ReleaseError("unsafe legacy singleton lock")
            deadline = time.monotonic() + self.switch_timeout
            while True:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    locked = True
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise ReleaseError(
                            "timed out waiting for the legacy singleton lock"
                        )
                    time.sleep(0.02)
            named = os.stat(
                ".grok-remote.lock", dir_fd=parent_fd, follow_symlinks=False
            )
            if (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino):
                raise ReleaseError("legacy singleton lock identity changed")
            os.fchmod(lock_fd, 0o600)
            os.fsync(lock_fd)
            if created:
                os.fsync(parent_fd)
            yield
            current = os.fstat(lock_fd)
            named = os.stat(
                ".grok-remote.lock", dir_fd=parent_fd, follow_symlinks=False
            )
            if (
                not stat.S_ISREG(current.st_mode)
                or current.st_uid != self.layout.target_uid
                or current.st_gid != self.layout.target_gid
                or stat.S_IMODE(current.st_mode) != 0o600
                or current.st_size != 0
                or current.st_nlink != 1
                or (named.st_dev, named.st_ino)
                != (current.st_dev, current.st_ino)
            ):
                raise ReleaseError("legacy singleton lock changed while held")
        finally:
            if lock_fd >= 0:
                if locked:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)
            os.close(parent_fd)

    def _run_gate_smoke(
        self,
        gate: Path,
        argv: tuple[str, ...],
        *,
        uid: int,
        gid: int,
        inventory_release_id: str | None = None,
        timeout: float = 15.0,
        output_limit: int = 128 * 1024,
        work_deadline_monotonic_ns: int | None = None,
    ) -> SmokeResult:
        """Run a gate for ``timeout`` plus a fixed containment-only margin."""

        if timeout <= 0 or timeout > 60 or output_limit < 1024:
            raise ReleaseError("invalid release canary execution bounds")
        started_ns = time.monotonic_ns()
        local_deadline_monotonic_ns = started_ns + int(timeout * 1_000_000_000)
        if work_deadline_monotonic_ns is not None:
            if (
                type(work_deadline_monotonic_ns) is not int
                or work_deadline_monotonic_ns <= started_ns
            ):
                raise ReleaseError("release canary work deadline expired before spawn")
            local_deadline_monotonic_ns = min(
                local_deadline_monotonic_ns,
                work_deadline_monotonic_ns,
            )
        auth_fd = os.open(
            self.layout.canary_auth,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        started = time.monotonic()
        containment_deadline_monotonic_ns = (
            local_deadline_monotonic_ns
            + int(
                GATE_SMOKE_CONTAINMENT_SECONDS * 1_000_000_000
            )
        )
        process: subprocess.Popen[bytes] | None = None
        runner_scope: _RunnerCgroup | None = None
        leader_pidfd = -1
        session_reaped = False
        stdout = bytearray()
        stderr = bytearray()
        failure: str | None = None
        selector = selectors.DefaultSelector()
        try:
            auth_info = os.fstat(auth_fd)
            if (
                not stat.S_ISREG(auth_info.st_mode)
                or auth_info.st_uid != self.layout.root_uid
                or auth_info.st_gid != self.layout.root_gid
                or stat.S_IMODE(auth_info.st_mode) != 0o600
            ):
                raise ReleaseError("fixed canary authorization changed identity")
            home = self.layout.user_root.parents[2]
            environment = {
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "HOME": str(home if uid == self.layout.target_uid else Path("/root")),
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "GROK_MULTI_SESSION": "0",
                "GROK_RELEASE_CANARY_FD": str(auth_fd),
            }
            if self.layout.test_install:
                environment["GROK_TESTING"] = "1"
            if inventory_release_id is not None:
                if RELEASE_ID_RE.fullmatch(inventory_release_id) is None:
                    raise ReleaseError("invalid broker inventory release ID")
                environment.update(
                    {
                        "GROK_RELEASE_INVENTORY_FD": str(auth_fd),
                        "GROK_RELEASE_INVENTORY_RELEASE_ID": inventory_release_id,
                    }
                )
                if self.layout.test_install:
                    environment.update(
                        {
                            "GROK_TEST_ROOT_RELEASE_CONTROL": str(
                                self.layout.root_control
                            ),
                            "GROK_TEST_ROOT_ROOT": str(self.layout.root_root),
                            "GROK_TEST_BROKER_STATE": str(
                                self.layout.broker_state
                            ),
                        }
                    )
            demote = self._drop_identity(uid, gid)
            if self._runner_scopes_required():
                runner_scope = self._create_runner_scope(
                    uid,
                    gid,
                    containment_deadline_monotonic_ns,
                    runner_kind="gate-smoke",
                    release_id=inventory_release_id,
                )
            inherited = (
                (auth_fd, runner_scope.descriptor)
                if runner_scope is not None
                else (auth_fd,)
            )
            process = subprocess.Popen(
                [str(gate), *argv],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
                pass_fds=inherited,
                start_new_session=True,
                env=environment,
                preexec_fn=(
                    runner_scope.preexec(demote)
                    if runner_scope is not None
                    else demote
                ),
            )
            if runner_scope is not None:
                runner_scope.mark_running()
            leader_pidfd = os.pidfd_open(process.pid, 0)
            os.set_inheritable(leader_pidfd, False)
            assert process.stdout is not None and process.stderr is not None
            streams = {
                process.stdout.fileno(): stdout,
                process.stderr.fileno(): stderr,
            }
            for descriptor in streams:
                os.set_blocking(descriptor, False)
                selector.register(descriptor, selectors.EVENT_READ)
            while streams:
                remaining_ns = (
                    local_deadline_monotonic_ns - time.monotonic_ns()
                )
                if remaining_ns <= 0:
                    failure = "timeout"
                    break
                events = selector.select(
                    min(remaining_ns / 1_000_000_000, 0.1)
                )
                for key, _mask in events:
                    descriptor = int(key.fd)
                    try:
                        chunk = os.read(descriptor, 8192)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(descriptor)
                        streams.pop(descriptor, None)
                        continue
                    streams[descriptor].extend(chunk)
                    if len(stdout) + len(stderr) > output_limit:
                        failure = "output-limit"
                        break
                if failure is not None:
                    break
            if runner_scope is not None:
                runner_scope.cleanup(containment_deadline_monotonic_ns)
                returncode = _reap_after_cgroup_cleanup(
                    process,
                    leader_pidfd,
                    deadline_monotonic_ns=containment_deadline_monotonic_ns,
                )
                runner_scope.finalize_record()
            else:
                returncode = _kill_session_group_before_reap(
                    process,
                    leader_pidfd,
                    graceful_seconds=0.0 if failure is not None else 2.0,
                    deadline_monotonic_ns=containment_deadline_monotonic_ns,
                )
            session_reaped = True
            if failure is not None:
                stderr.extend(f"\ninstaller-canary:{failure}\n".encode("ascii"))
                returncode = 124 if failure == "timeout" else 125
            return SmokeResult(
                returncode,
                bytes(stdout[:output_limit]),
                bytes(stderr[:output_limit]),
                min(300_000, max(0, int((time.monotonic() - started) * 1000))),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ReleaseError(f"cannot execute exact release canary: {exc}") from exc
        finally:
            selector.close()
            containment_error: BaseException | None = None
            if runner_scope is not None:
                try:
                    runner_scope.cleanup(containment_deadline_monotonic_ns)
                except BaseException as exc:
                    containment_error = exc
                finally:
                    runner_scope.close()
            if (
                process is not None
                and not session_reaped
                and _session_is_quarantined(process)
            ):
                session_reaped = True
            if (
                process is not None
                and not session_reaped
                and process.returncode is not None
            ):
                session_reaped = True
            if process is not None and not session_reaped:
                try:
                    if runner_scope is not None and runner_scope.scope_removed:
                        _reap_after_cgroup_cleanup(
                            process,
                            leader_pidfd,
                            deadline_monotonic_ns=(
                                containment_deadline_monotonic_ns
                            ),
                        )
                    elif leader_pidfd >= 0:
                        _kill_session_group_before_reap(
                            process,
                            leader_pidfd,
                            graceful_seconds=0.0,
                            deadline_monotonic_ns=(
                                containment_deadline_monotonic_ns
                            ),
                        )
                    else:
                        _kill_session_group_without_pidfd_before_reap(
                            process,
                            deadline_monotonic_ns=(
                                containment_deadline_monotonic_ns
                            ),
                        )
                    session_reaped = True
                except BaseException as exc:
                    containment_error = containment_error or exc
            if (
                runner_scope is not None
                and runner_scope.scope_removed
                and (process is None or session_reaped)
                and not runner_scope.cleaned
            ):
                try:
                    runner_scope.finalize_record()
                except BaseException as exc:
                    containment_error = containment_error or exc
            if process is not None:
                for stream in (process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()
            if leader_pidfd >= 0:
                os.close(leader_pidfd)
            os.close(auth_fd)
            if containment_error is not None:
                raise containment_error

    def _bootstrap_legacy_migration(self, release_id: str) -> dict[str, object]:
        """Run the exact target broker's install-only inert migration."""

        with self._legacy_singleton_locked():
            inventory = self._broker_inventory(allow_root_artifact_residue=True)
            if inventory.get("root_artifact_residue") is False:
                suspects = self._legacy_openvpn_process_inventory()
                if suspects:
                    raise ReleaseError(
                        "legacy OpenVPN process blocks empty migration evidence: "
                        f"count={len(suspects)}"
                    )
                # This no-op path is intentionally expressed in the current
                # installer's evidence schema.  It also lets a fenced release
                # published by an older installer converge once strict root
                # inventory already proves that no migration is required.
                return {
                    "ok": True,
                    "active": False,
                    "migrated": False,
                    "pre_root_artifact_residue": False,
                    "post_root_artifact_residue": False,
                    "release_id": release_id,
                }
            result = self._run_gate_smoke(
                self.layout.broker_entrypoint,
                ("--release-bootstrap-migrate",),
                uid=self.layout.root_uid,
                gid=self.layout.root_gid,
                inventory_release_id=release_id,
                timeout=60.0,
            )
        if result.returncode != 0:
            raise ReleaseError(
                "installer-authenticated legacy migration failed with exit "
                f"{result.returncode}; "
                + _bounded_output_diagnostic(result.stdout, result.stderr)
            )
        try:
            value = json.loads(result.stdout)
        except (UnicodeDecodeError, ValueError) as exc:
            raise ReleaseError(
                "invalid installer-authenticated legacy migration result; "
                + _bounded_output_diagnostic(result.stdout, result.stderr)
            ) from exc
        fields = {
            "ok", "active", "migrated", "pre_root_artifact_residue",
            "post_root_artifact_residue", "release_id",
        }
        if (
            not isinstance(value, dict)
            or set(value) != fields
            or value.get("ok") is not True
            or value.get("active") is not False
            or type(value.get("migrated")) is not bool
            or type(value.get("pre_root_artifact_residue")) is not bool
            or value.get("post_root_artifact_residue") is not False
            or value.get("release_id") != release_id
            or value.get("migrated")
            is not value.get("pre_root_artifact_residue")
        ):
            raise ReleaseError(
                "installer-authenticated legacy migration did not prove empty"
            )
        return value

    def _produce_evidence(
        self,
        release_id: str,
        operation: str,
        legacy_migration: Mapping[str, object],
    ) -> dict[str, object]:
        user, root = self.validate_release_pair(release_id)
        target_root_files = self._target_root_files(release_id)
        criteria: list[dict[str, object]] = [
            self._criterion(
                "release-pair",
                True,
                {
                    "user": user["release_id"],
                    "root": root["release_id"],
                },
            ),
            self._criterion(
                "target-root-map",
                True,
                target_root_files,
            ),
            self._criterion(
                "legacy-root-migration",
                True,
                dict(legacy_migration),
            ),
        ]
        commands = (
            (
                "compatibility-matrix",
                self.layout.entrypoint,
                ("--release-compatibility-smoke",),
                self.layout.target_uid,
                self.layout.target_gid,
            ),
            (
                "broker-status-helper-map",
                self.layout.broker_entrypoint,
                ("--release-root-inventory",),
                self.layout.root_uid,
                self.layout.root_gid,
            ),
        )
        for criterion_id, gate, argv, uid, gid in commands:
            result = self._run_gate_smoke(gate, argv, uid=uid, gid=gid)
            criteria.append(
                self._criterion(
                    criterion_id,
                    result.returncode == 0,
                    {
                        "returncode": result.returncode,
                        "stdout_sha256": _sha256_bytes(result.stdout),
                        "stderr_sha256": _sha256_bytes(result.stderr),
                    },
                    result.duration_ms,
                )
            )
        inventory_error: str | None = None
        inventory_snapshot: object = {"quiescent": True}
        try:
            inventory_snapshot = self._assert_switch_quiescent()
        except ReleaseError as exc:
            inventory_error = str(exc)
        criteria.append(
            self._criterion(
                "multi-root-inventory-empty",
                inventory_error is None,
                {
                    "error": inventory_error,
                    "inventory_sha256": _sha256_bytes(
                        _canonical_json(inventory_snapshot)
                    ),
                },
            )
        )
        if inventory_error is None:
            self._write_boot_inventory(release_id, inventory_snapshot)
        user_manifest = self.layout.user_releases / release_id / "release.json"
        root_manifest = self.layout.root_releases / release_id / "release.json"
        return {
            "schema_version": EVIDENCE_SCHEMA_VERSION,
            "release_id": release_id,
            "operation": operation,
            "host_id": self._host_id(),
            "created_unix_ns": time.time_ns(),
            "user_manifest_sha256": _sha256_bytes(
                _read_regular(
                    user_manifest,
                    uid=self.layout.root_uid,
                    gid=self.layout.root_gid,
                    mode=0o444,
                )[0]
            ),
            "root_manifest_sha256": _sha256_bytes(
                _read_regular(
                    root_manifest,
                    uid=self.layout.root_uid,
                    gid=self.layout.root_gid,
                    mode=0o444,
                )[0]
            ),
            "root_files": target_root_files,
            "criteria": criteria,
            "overall_pass": all(criterion["passed"] is True for criterion in criteria),
        }

    def _write_evidence(self, record: Mapping[str, object]) -> str:
        release_id = record.get("release_id")
        if type(release_id) is not str or RELEASE_ID_RE.fullmatch(release_id) is None:
            raise ReleaseError("cannot publish evidence with an invalid release ID")
        data = _canonical_json(dict(record)) + b"\n"
        _atomic_write(
            self.layout.evidence_path(release_id),
            data,
            mode=0o444,
            uid=self.layout.root_uid,
            gid=self.layout.root_gid,
            parent_mode=0o755,
        )
        return _sha256_bytes(data)

    def _validate_evidence(self, release_id: str, operation: str) -> str:
        path = self.layout.evidence_path(release_id)
        raw, _mode = _read_regular(
            path,
            uid=self.layout.root_uid,
            gid=self.layout.root_gid,
            mode=0o444,
            maximum=1024 * 1024,
        )
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, ValueError) as exc:
            raise ReleaseError(f"cannot parse promotion evidence {path}: {exc}") from exc
        fields = {
            "schema_version", "release_id", "operation", "host_id",
            "created_unix_ns", "user_manifest_sha256", "root_manifest_sha256",
            "root_files", "criteria", "overall_pass",
        }
        if not isinstance(value, dict) or set(value) != fields:
            raise ReleaseError("promotion evidence has an unexpected shape")
        target_root_files = self._target_root_files(release_id)
        user_manifest = self.layout.user_releases / release_id / "release.json"
        root_manifest = self.layout.root_releases / release_id / "release.json"
        if (
            value.get("schema_version") != EVIDENCE_SCHEMA_VERSION
            or value.get("release_id") != release_id
            or value.get("operation") != operation
            or value.get("host_id") != self._host_id()
            or type(value.get("created_unix_ns")) is not int
            or value.get("created_unix_ns", 0) <= 0
            or value.get("user_manifest_sha256")
            != _sha256_bytes(
                _read_regular(
                    user_manifest,
                    uid=self.layout.root_uid,
                    gid=self.layout.root_gid,
                    mode=0o444,
                )[0]
            )
            or value.get("root_manifest_sha256")
            != _sha256_bytes(
                _read_regular(
                    root_manifest,
                    uid=self.layout.root_uid,
                    gid=self.layout.root_gid,
                    mode=0o444,
                )[0]
            )
            or value.get("root_files") != target_root_files
            or value.get("overall_pass") is not True
        ):
            raise ReleaseError("promotion evidence does not bind a passing target")
        criteria = value.get("criteria")
        if not isinstance(criteria, list) or len(criteria) != len(EVIDENCE_CRITERIA):
            raise ReleaseError("promotion evidence criteria are incomplete")
        for expected_id, criterion in zip(EVIDENCE_CRITERIA, criteria):
            if (
                not isinstance(criterion, dict)
                or set(criterion)
                != {"id", "passed", "result_sha256", "duration_ms"}
                or criterion.get("id") != expected_id
                or criterion.get("passed") is not True
                or type(criterion.get("result_sha256")) is not str
                or RELEASE_ID_RE.fullmatch(str(criterion.get("result_sha256"))) is None
                or type(criterion.get("duration_ms")) is not int
                or not 0 <= criterion.get("duration_ms", -1) <= 300_000
            ):
                raise ReleaseError(
                    f"promotion evidence criterion is failed/mismatched: {expected_id}"
                )
        return _sha256_bytes(raw)

    def _selection_is_exact(
        self,
        release_id: str,
        *,
        permit_deny: bool = False,
        expected_phase: str = "READY",
    ) -> bool:
        try:
            if expected_phase not in {"CANARY", "READY"}:
                return False
            if not permit_deny and _present(self.layout.rollback_deny):
                return False
            target_root_files = self._target_root_files(release_id)
            _verify_dir(
                self.layout.user_releases / release_id,
                ACTIVE_RELEASE_MODE,
                self.layout.root_uid,
                self.layout.root_gid,
            )
            _verify_dir(
                self.layout.root_releases / release_id,
                ACTIVE_RELEASE_MODE,
                self.layout.root_uid,
                self.layout.root_gid,
            )
            if self.active_release_id() != release_id or self.root_active_release_id() != release_id:
                return False
            entrypoint_bytes = self._gate_source(
                release_id, "user", target_root_files=target_root_files
            )
            broker_bytes = self._gate_source(
                release_id, "broker", target_root_files=target_root_files
            )
            actual_entrypoint, _ = _read_regular(
                self.layout.entrypoint,
                uid=self.layout.root_uid,
                gid=self.layout.root_gid,
                mode=0o555,
            )
            actual_broker, _ = _read_regular(
                self.layout.broker_entrypoint,
                uid=self.layout.root_uid,
                gid=self.layout.root_gid,
                mode=0o555,
            )
            if actual_entrypoint != entrypoint_bytes or actual_broker != broker_bytes:
                return False
            root_record = self._read_json(
                self.layout.root_selected,
                uid=self.layout.root_uid,
                gid=self.layout.root_gid,
                mode=0o444,
            )
            user_raw, _ = _read_regular(
                self.layout.selected,
                uid=self.layout.target_uid,
                gid=self.layout.target_gid,
                mode=0o444,
            )
            user_record = json.loads(user_raw)
            if not isinstance(user_record, dict):
                return False
            user_digest = root_record.pop("user_selection_sha256", None)
            if user_digest != _sha256_bytes(user_raw) or root_record != user_record:
                return False
            operation = user_record.get("operation")
            if operation not in ("install", "rollback"):
                return False
            if user_record.get("selection_phase") != expected_phase:
                return False
            selected_rungs = user_record.get("qualified_rungs")
            if not isinstance(selected_rungs, list):
                return False
            qualified_rungs = (
                []
                if expected_phase == "CANARY"
                else self._validate_qualified_rungs(release_id, selected_rungs)
            )
            evidence_sha256 = (
                ZERO_DIGEST
                if expected_phase == "CANARY"
                else self._validate_evidence(release_id, str(operation))
            )
            expected_user, expected_root = self._selection_records(
                release_id,
                str(operation),
                entrypoint_bytes,
                broker_bytes,
                target_root_files=target_root_files,
                evidence_sha256=evidence_sha256,
                selection_phase=expected_phase,
                qualified_rungs=qualified_rungs,
            )
            return (
                user_record == expected_user
                and {
                    **root_record,
                    "user_selection_sha256": user_digest,
                }
                == expected_root
                and self._release_access_is_exact(release_id)
            )
        except (OSError, ReleaseError, ValueError):
            return False

    @staticmethod
    def _proc_start_ticks(
        pid: int,
        inventory_budget: _SwitchInventoryBudget | None = None,
    ) -> int:
        path = Path(f"/proc/{pid}/stat")
        if inventory_budget is None:
            raw = path.read_text(encoding="ascii")
        else:
            try:
                raw = inventory_budget.read_path(
                    path,
                    MAX_SWITCH_PROC_RECORD_BYTES,
                    "process identity inventory",
                ).decode("ascii")
            except UnicodeDecodeError as exc:
                raise ReleaseError("supervisor /proc stat is non-ASCII") from exc
        close = raw.rfind(")")
        if close < 0:
            raise ReleaseError("supervisor /proc stat is malformed")
        fields = raw[close + 2 :].split()
        if len(fields) < 20:
            raise ReleaseError("supervisor /proc stat is truncated")
        value = int(fields[19])
        if value <= 0:
            raise ReleaseError("supervisor start time is invalid")
        return value

    def _live_supervisor_pidfd(
        self,
        *,
        deadline_monotonic_ns: int | None = None,
    ) -> tuple[int, int] | None:
        """Return an exact pidfd for the fenced supervisor, or fail closed."""

        if deadline_monotonic_ns is None:
            deadline_monotonic_ns = (
                time.monotonic_ns() + int(self.switch_timeout * 1_000_000_000)
            )
        budget = _SwitchInventoryBudget(deadline_monotonic_ns)
        budget.check("supervisor fence inventory")
        layout = self.layout
        if not _present(layout.recovery_fence):
            return None
        value = self._read_json(
            layout.recovery_fence,
            uid=layout.target_uid,
            gid=layout.target_gid,
            mode=0o600,
        )
        budget.check("supervisor fence inventory")
        fields = {
            "schema_version",
            "release_id",
            "owner_epoch",
            "pid",
            "pid_start_ticks",
            "boot_id",
            "phase",
        }
        if set(value) != fields:
            raise ReleaseError("multi-session recovery fence has an unexpected shape")
        release_id = value.get("release_id")
        owner_epoch = value.get("owner_epoch")
        pid = value.get("pid")
        start_ticks = value.get("pid_start_ticks")
        boot_id = value.get("boot_id")
        phase = value.get("phase")
        token = re.compile(r"^[A-Za-z0-9._:+@-]{1,256}$")
        boot = re.compile(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        )
        if (
            value.get("schema_version") != CONTROL_SCHEMA_VERSION
            or type(release_id) is not str
            or RELEASE_ID_RE.fullmatch(release_id) is None
            or type(owner_epoch) is not str
            or token.fullmatch(owner_epoch) is None
            or type(pid) is not int
            or not 1 <= pid < 2**31
            or type(start_ticks) is not int
            or not 1 <= start_ticks < 2**63
            or type(boot_id) is not str
            or boot.fullmatch(boot_id) is None
            or phase not in {"BOOTSTRAPPING", "RECOVERING", "READY", "DRAINING"}
        ):
            raise ReleaseError("multi-session recovery fence is invalid")
        assert isinstance(pid, int) and isinstance(start_ticks, int)
        assert isinstance(release_id, str) and isinstance(boot_id, str)
        try:
            running_boot = budget.read_path(
                Path("/proc/sys/kernel/random/boot_id"),
                128,
                "supervisor boot identity inventory",
            ).decode("ascii").strip()
            if (
                running_boot != boot_id
                or self._proc_start_ticks(pid, budget) != start_ticks
            ):
                raise ReleaseError(
                    "multi-session fence owner is not live; explicit recovery is required"
                )
            status = budget.read_path(
                Path(f"/proc/{pid}/status"),
                MAX_SWITCH_PROC_RECORD_BYTES,
                "supervisor status inventory",
            ).decode("ascii")
            uid_line = next(
                (line for line in status.splitlines() if line.startswith("Uid:")), None
            )
            if uid_line is None or int(uid_line.split()[1]) != layout.target_uid:
                raise ReleaseError("recorded supervisor has the wrong user identity")
            cmdline = budget.read_path(
                Path(f"/proc/{pid}/cmdline"),
                MAX_SWITCH_PROC_RECORD_BYTES,
                "supervisor command identity inventory",
            ).split(b"\0")
            if cmdline and cmdline[-1] == b"":
                cmdline.pop()
            argv = [item.decode("utf-8", "strict") for item in cmdline]
            release_dir = layout.user_releases / release_id
            fixed_prefix = [
                "/usr/bin/python3",
                "-E",
                "-s",
                "-m",
                "grok_ms.supervisor",
                "--release-dir",
                str(release_dir),
                "--control-root",
                str(layout.multi_control),
                "--expected-contract",
            ]
            expected_tail = argv[13:]
            warm_tail_ok = (
                expected_tail
                in (
                    ["--scoped-bootstrap"],
                    ["--scoped-bootstrap", "--warm-legacy-handoff"],
                )
                if layout.test_install
                else expected_tail
                == ["--scoped-bootstrap", "--warm-legacy-handoff"]
            )
            if (
                len(argv) not in {14, 15}
                or argv[: len(fixed_prefix)] != fixed_prefix
                or RELEASE_ID_RE.fullmatch(argv[10]) is None
                or argv[11] != "--expected-control-cap"
                or not argv[12].isdecimal()
                or not 3 <= int(argv[12]) <= 65_536
                or not warm_tail_ok
            ):
                raise ReleaseError("recorded supervisor command line is not exact")
            if Path(f"/proc/{pid}/cwd").resolve(strict=True) != release_dir:
                raise ReleaseError("recorded supervisor working directory is not exact")
            budget.check("supervisor working directory inventory")
            if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
                raise ReleaseError("pidfd signalling is required for controlled release drain")
            pidfd = os.pidfd_open(pid, 0)
            os.set_inheritable(pidfd, False)
            if self._proc_start_ticks(pid, budget) != start_ticks:
                os.close(pidfd)
                raise ReleaseError("recorded supervisor changed during pidfd acquisition")
            return pid, pidfd
        except FileNotFoundError as exc:
            raise ReleaseError(
                "multi-session fence owner disappeared; explicit recovery is required"
            ) from exc
        except (UnicodeDecodeError, ValueError, OSError) as exc:
            raise ReleaseError(f"cannot verify fenced supervisor exactly: {exc}") from exc

    def _drain_active(
        self,
        *,
        allow_root_artifact_residue: bool = False,
    ) -> None:
        """Terminate one exact live epoch and prove all release-bound residue empty."""

        deadline_monotonic_ns = (
            time.monotonic_ns() + int(self.switch_timeout * 1_000_000_000)
        )
        owned = self._live_supervisor_pidfd(
            deadline_monotonic_ns=deadline_monotonic_ns
        )
        if owned is None:
            self._assert_switch_quiescent(
                allow_root_artifact_residue=allow_root_artifact_residue,
                deadline_monotonic_ns=deadline_monotonic_ns,
            )
            return
        pid, pidfd = owned
        identity_budget = _SwitchInventoryBudget(deadline_monotonic_ns)
        try:
            signal.pidfd_send_signal(pidfd, signal.SIGTERM)
            while time.monotonic_ns() < deadline_monotonic_ns:
                try:
                    os.waitid(os.P_PIDFD, pidfd, os.WEXITED | os.WNOHANG)
                except ChildProcessError:
                    pass
                try:
                    self._proc_start_ticks(pid, identity_budget)
                except (FileNotFoundError, ProcessLookupError, OSError):
                    break
                time.sleep(
                    min(
                        0.02,
                        max(
                            0.0,
                            (deadline_monotonic_ns - time.monotonic_ns())
                            / 1_000_000_000,
                        ),
                    )
                )
            else:
                raise ReleaseError("timed out draining the exact multi-session supervisor")
        finally:
            os.close(pidfd)

        last_error: ReleaseError | None = None
        while time.monotonic_ns() < deadline_monotonic_ns:
            try:
                self._assert_switch_quiescent(
                    allow_root_artifact_residue=allow_root_artifact_residue,
                    deadline_monotonic_ns=deadline_monotonic_ns,
                )
                return
            except ReleaseError as exc:
                last_error = exc
                remaining = (
                    deadline_monotonic_ns - time.monotonic_ns()
                ) / 1_000_000_000
                if remaining > 0:
                    time.sleep(min(0.02, remaining))
        raise ReleaseError(f"multi-session drain left residue: {last_error}")

    def _legacy_openvpn_process_inventory(
        self,
        inventory_budget: _SwitchInventoryBudget | None = None,
    ) -> list[int]:
        """Return every definite or ambiguous fixed legacy OpenVPN process."""

        if inventory_budget is None:
            inventory_budget = _SwitchInventoryBudget(
                time.monotonic_ns() + int(self.switch_timeout * 1_000_000_000)
            )
        inventory_budget.check("legacy process inventory")
        prefix = self.layout.root_control.parents[3]
        work = prefix / "var/lib/grok-vpngate"
        legacy_paths = {
            str(work / "vpngate.ovpn"),
            str(work / "openvpn.pid"),
            str(work / "openvpn.start"),
            str(work / "openvpn.boot"),
        }
        directory_flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        def argv_pair(argv: tuple[str, ...], option: str, value: str) -> bool:
            return any(
                argv[index] == option and argv[index + 1] == value
                for index in range(len(argv) - 1)
            )

        try:
            proc_fd = os.open("/proc", directory_flags)
        except OSError as exc:
            raise ReleaseError("cannot inspect legacy OpenVPN process inventory") from exc
        suspects: list[int] = []
        try:
            with os.scandir(proc_fd) as entries:
                for entry in entries:
                    inventory_budget.consume_entry("legacy process inventory")
                    name = entry.name
                    if not name.isdecimal() or not 1 <= int(name) <= 2**31 - 1:
                        continue
                    try:
                        process_fd = os.open(name, directory_flags, dir_fd=proc_fd)
                    except FileNotFoundError:
                        continue
                    except OSError as exc:
                        raise ReleaseError(
                            f"cannot inspect process {name} for legacy OpenVPN"
                        ) from exc
                    try:
                        try:
                            comm = inventory_budget.read_at(
                                process_fd,
                                "comm",
                                256,
                                "legacy process inventory",
                            ).rstrip(b"\n").decode("utf-8", "surrogateescape")
                            raw = inventory_budget.read_at(
                                process_fd,
                                "cmdline",
                                MAX_SWITCH_PROC_RECORD_BYTES,
                                "legacy process inventory",
                            )
                            argv = tuple(
                                item.decode("utf-8", "surrogateescape")
                                for item in raw.rstrip(b"\0").split(b"\0")
                                if item
                            )
                        except FileNotFoundError:
                            continue
                        try:
                            executable = os.readlink("exe", dir_fd=process_fd)
                            inventory_budget.consume_bytes(
                                len(executable.encode("utf-8", "surrogateescape")),
                                "legacy process inventory",
                            )
                        except OSError:
                            executable = ""
                        openvpn_identity = bool(
                            comm == "openvpn"
                            or Path(executable).name == "openvpn"
                            or (argv and Path(argv[0]).name == "openvpn")
                        )
                        legacy_marker = any(
                            argument in legacy_paths
                            or any(
                                argument == f"{option}={path}"
                                for option in ("--config", "--writepid", "--log")
                                for path in legacy_paths
                            )
                            for argument in argv
                        ) or any(
                            argv_pair(argv, option, value)
                            for option, value in (
                                ("--config", str(work / "vpngate.ovpn")),
                                ("--writepid", str(work / "openvpn.pid")),
                                ("--dev", "tun-grok"),
                                ("--daemon", "grok-vpngate"),
                            )
                        )
                        if openvpn_identity or legacy_marker:
                            suspects.append(int(name))
                    except OSError as exc:
                        try:
                            os.stat(name, dir_fd=proc_fd, follow_symlinks=False)
                        except FileNotFoundError:
                            continue
                        raise ReleaseError(
                            f"cannot rule out legacy OpenVPN process {name}"
                        ) from exc
                    finally:
                        os.close(process_fd)
        finally:
            os.close(proc_fd)
        return sorted(suspects)

    def _release_bound_process_inventory(
        self,
        inventory_budget: _SwitchInventoryBudget | None = None,
    ) -> list[dict[str, object]]:
        if inventory_budget is None:
            inventory_budget = _SwitchInventoryBudget(
                time.monotonic_ns() + int(self.switch_timeout * 1_000_000_000)
            )
        inventory_budget.check("release process inventory")
        roots = (self.layout.user_releases, self.layout.root_releases)

        def bound(value: str) -> bool:
            if not value.startswith("/"):
                return False
            candidate = Path(value)
            return any(candidate == root or root in candidate.parents for root in roots)

        directory_flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        records: list[dict[str, object]] = []
        proc_fd = os.open("/proc", directory_flags)
        try:
            with os.scandir(proc_fd) as entries:
                for entry in entries:
                    inventory_budget.consume_entry("release process inventory")
                    if not entry.name.isdecimal():
                        continue
                    pid = int(entry.name)
                    try:
                        process_fd = os.open(
                            entry.name,
                            directory_flags,
                            dir_fd=proc_fd,
                        )
                    except FileNotFoundError:
                        continue
                    try:
                        status = inventory_budget.read_at(
                            process_fd,
                            "status",
                            MAX_SWITCH_PROC_RECORD_BYTES,
                            "release process inventory",
                        ).decode("ascii")
                        uid_row = next(
                            row for row in status.splitlines() if row.startswith("Uid:")
                        )
                        uid = int(uid_row.split()[1])
                        if uid not in {self.layout.target_uid, self.layout.root_uid}:
                            continue
                        values: list[str] = []
                        for name in ("cwd", "exe"):
                            try:
                                value = os.readlink(name, dir_fd=process_fd)
                                inventory_budget.consume_bytes(
                                    len(value.encode("utf-8", "surrogateescape")),
                                    "release process inventory",
                                )
                                values.append(value)
                            except OSError:
                                pass
                        cmdline = inventory_budget.read_at(
                            process_fd,
                            "cmdline",
                            MAX_SWITCH_PROC_RECORD_BYTES,
                            "release process inventory",
                        ).split(b"\0")
                        values.extend(
                            item.decode("utf-8", "strict") for item in cmdline if item
                        )
                        matched = sorted({value for value in values if bound(value)})
                        if matched:
                            records.append(
                                {
                                    "pid": pid,
                                    "start_ticks": self._proc_start_ticks(
                                        pid, inventory_budget
                                    ),
                                    "uid": uid,
                                    "release_paths": matched,
                                }
                            )
                    except (FileNotFoundError, ProcessLookupError):
                        continue
                    except (OSError, StopIteration, UnicodeDecodeError, ValueError) as exc:
                        raise ReleaseError(
                            f"cannot prove release-bound process inventory for PID {pid}: {exc}"
                        ) from exc
                    finally:
                        os.close(process_fd)
        finally:
            os.close(proc_fd)
        return sorted(records, key=lambda value: int(value["pid"]))

    def _fixed_listener_inventory(
        self,
        inventory_budget: _SwitchInventoryBudget | None = None,
    ) -> list[dict[str, int]]:
        if inventory_budget is None:
            inventory_budget = _SwitchInventoryBudget(
                time.monotonic_ns() + int(self.switch_timeout * 1_000_000_000)
            )
        inventory_budget.check("TCP listener inventory")
        owned_ports = {1080, 11080, 11081}
        records: set[tuple[int, int]] = set()
        for table in (Path("/proc/self/net/tcp"), Path("/proc/self/net/tcp6")):
            try:
                rows = inventory_budget.read_path(
                    table,
                    MAX_SWITCH_INVENTORY_BYTES,
                    "TCP listener inventory",
                ).decode("ascii").splitlines()
            except (OSError, UnicodeDecodeError) as exc:
                raise ReleaseError(f"cannot inspect TCP listener inventory: {exc}") from exc
            for row in rows[1:]:
                inventory_budget.consume_entry("TCP listener inventory")
                fields = row.split()
                if len(fields) < 10 or fields[3] != "0A":
                    continue
                try:
                    port = int(fields[1].rsplit(":", 1)[1], 16)
                    inode = int(fields[9])
                except (IndexError, ValueError) as exc:
                    raise ReleaseError("malformed TCP listener inventory") from exc
                if port in owned_ports:
                    records.add((port, inode))
        return [
            {"port": port, "socket_inode": inode}
            for port, inode in sorted(records)
        ]

    def _fixed_cgroup_inventory(
        self,
        inventory_budget: _SwitchInventoryBudget | None = None,
    ) -> list[str]:
        if inventory_budget is None:
            inventory_budget = _SwitchInventoryBudget(
                time.monotonic_ns() + int(self.switch_timeout * 1_000_000_000)
            )
        inventory_budget.check("cgroup-v2 inventory")
        production = (
            self.layout.root_root == Path("/usr/local/libexec/grok-proxy")
            and self.layout.root_control
            == Path("/var/lib/grok-proxy/release-control")
        )
        if not production:
            return []
        root = Path("/sys/fs/cgroup")
        patterns = (
            re.compile(r"^grok-ms-[0-9a-f]{24}$"),
            re.compile(r"^grok-installer-[0-9a-f]{24}$"),
            re.compile(r"^grok-vpn-[0-9a-f]{24}$"),
            re.compile(r"^grok-vpn-broker-[0-9]+$"),
        )
        found: list[str] = []
        try:
            pending = [root]
            while pending:
                inventory_budget.check("cgroup-v2 inventory")
                directory = pending.pop()
                with os.scandir(directory) as entries:
                    for entry in entries:
                        inventory_budget.consume_entry("cgroup-v2 inventory")
                        if any(pattern.fullmatch(entry.name) for pattern in patterns):
                            found.append(str(Path(entry.path)))
                        if entry.is_dir(follow_symlinks=False):
                            pending.append(Path(entry.path))
        except OSError as exc:
            raise ReleaseError(f"cannot inspect cgroup-v2 inventory: {exc}") from exc
        return sorted(found)

    def _root_selected_broker(
        self,
        inventory_budget: _SwitchInventoryBudget | None = None,
    ) -> tuple[str, Path, dict[str, str]]:
        """Resolve the exact root-selected broker without trusting user selectors.

        Release switching may have durably advanced only some selectors.  Root
        inventory must remain available in that state, so it is pinned to the
        root selection record and immutable release tree rather than routed
        through the mutable fixed gate.  The broker independently revalidates
        this same root record and helper map before inspecting host state.
        """

        if inventory_budget is None:
            inventory_budget = _SwitchInventoryBudget(
                time.monotonic_ns() + int(self.switch_timeout * 1_000_000_000)
            )
        inventory_budget.check("root broker selection inventory")
        raw, _mode = _read_regular(
            self.layout.root_selected,
            uid=self.layout.root_uid,
            gid=self.layout.root_gid,
            mode=0o444,
            maximum=1024 * 1024,
        )
        inventory_budget.consume_bytes(
            len(raw), "root broker selection inventory"
        )
        try:
            selected = json.loads(raw)
        except (UnicodeDecodeError, ValueError) as exc:
            raise ReleaseError(f"cannot parse root release selection: {exc}") from exc
        release_id = selected.get("release_id") if isinstance(selected, dict) else None
        if (
            not isinstance(selected, dict)
            or type(release_id) is not str
            or RELEASE_ID_RE.fullmatch(release_id) is None
            or selected.get("schema_version") != CONTROL_SCHEMA_VERSION
            or selected.get("release_schema_version") != SCHEMA_VERSION
            or selected.get("handshake_protocol") != HANDSHAKE_PROTOCOL
            or selected.get("user_release_id") != release_id
            or selected.get("root_release_id") != release_id
            or selected.get("root_root") != str(self.layout.root_root)
            or selected.get("root_control") != str(self.layout.root_control)
        ):
            raise ReleaseError("root release selection cannot authorize inventory")
        root_files = selected.get("root_files")
        user_manifest, _root_manifest_value = self.validate_release_pair(
            release_id
        )
        identity = user_manifest.get("identity")
        if not isinstance(identity, dict):
            raise ReleaseError("root inventory release identity is invalid")
        expected_root_files = self._root_files_from_identity(
            identity, release_id
        )
        if root_files != expected_root_files:
            raise ReleaseError("root inventory helper map differs from release identity")
        root_manifest = self.layout.root_releases / release_id / "release.json"
        manifest_raw, _manifest_mode = _read_regular(
            root_manifest,
            uid=self.layout.root_uid,
            gid=self.layout.root_gid,
            mode=0o444,
            maximum=1024 * 1024,
        )
        inventory_budget.consume_bytes(
            len(manifest_raw), "root broker manifest inventory"
        )
        if _sha256_bytes(manifest_raw) != selected.get("root_manifest_sha256"):
            raise ReleaseError("root inventory manifest differs from root selection")
        broker = self.layout.root_releases / release_id / expected_root_files["broker"]
        broker_raw, _broker_mode = _read_regular(
            broker,
            uid=self.layout.root_uid,
            gid=self.layout.root_gid,
            mode=0o555,
            maximum=16 * 1024 * 1024,
        )
        inventory_budget.consume_bytes(
            len(broker_raw), "root broker executable inventory"
        )
        return release_id, broker, expected_root_files

    def _broker_inventory(
        self,
        *,
        allow_root_artifact_residue: bool = False,
        allow_active_runtime: bool = False,
        deadline_monotonic_ns: int | None = None,
        inventory_budget: _SwitchInventoryBudget | None = None,
    ) -> dict[str, object]:
        if deadline_monotonic_ns is None:
            deadline_monotonic_ns = (
                time.monotonic_ns() + int(self.switch_timeout * 1_000_000_000)
            )
        if inventory_budget is None:
            inventory_budget = _SwitchInventoryBudget(deadline_monotonic_ns)
        elif inventory_budget.deadline_monotonic_ns != deadline_monotonic_ns:
            raise ReleaseError("broker inventory deadline differs from its budget")
        inventory_budget.check("broker inventory")
        if allow_root_artifact_residue and allow_active_runtime:
            raise ReleaseError("broker inventory allowances conflict")
        if not _present(self.layout.broker_entrypoint):
            return {"status": "deferred-until-canary-selection"}
        if not _present(self.layout.root_selected):
            if (
                self.active_release_id() is not None
                or self.root_active_release_id() is not None
            ):
                raise ReleaseError(
                    "root selector exists without root selection metadata"
                )
            return {"status": "deferred-for-unselected-legacy-gate-replacement"}
        release_id, broker, root_files = self._root_selected_broker(inventory_budget)
        result = self._run_gate_smoke(
            broker,
            ("--release-root-inventory",),
            uid=self.layout.root_uid,
            gid=self.layout.root_gid,
            inventory_release_id=release_id,
            work_deadline_monotonic_ns=deadline_monotonic_ns,
        )
        inventory_budget.consume_bytes(
            len(result.stdout) + len(result.stderr),
            "broker inventory output",
        )
        if result.returncode != 0:
            raise ReleaseError(
                f"deny-safe broker inventory failed with exit {result.returncode}; "
                + _bounded_output_diagnostic(result.stdout, result.stderr)
            )
        try:
            value = json.loads(result.stdout)
        except (UnicodeDecodeError, ValueError) as exc:
            raise ReleaseError(
                "invalid deny-safe broker inventory; "
                + _bounded_output_diagnostic(result.stdout, result.stderr)
            ) from exc
        fields = {
            "ok", "active", "namespace_alive", "tun_alive", "host_tun_alive",
            "vpn_alive", "relay_alive", "root_artifact_residue", "ledger",
            "release_id", "root_files",
        }
        inactive_flags = (
            "active", "namespace_alive", "tun_alive", "host_tun_alive",
            "vpn_alive", "relay_alive",
        )
        empty = bool(
            isinstance(value, dict)
            and all(value.get(name) is False for name in inactive_flags)
            and value.get("root_artifact_residue") is False
            and value.get("ledger") is None
        )
        migratable = bool(
            allow_root_artifact_residue
            and isinstance(value, dict)
            and all(value.get(name) is False for name in inactive_flags)
            and type(value.get("root_artifact_residue")) is bool
            and value.get("ledger") is None
        )
        active_runtime = bool(
            allow_active_runtime
            and isinstance(value, dict)
            and value.get("active") is True
            and value.get("namespace_alive") is True
            and value.get("tun_alive") is True
            and value.get("host_tun_alive") is False
            and value.get("vpn_alive") is True
            and value.get("relay_alive") is True
            and value.get("root_artifact_residue") is True
            and isinstance(value.get("ledger"), dict)
        )
        if (
            not isinstance(value, dict)
            or set(value) != fields
            or value.get("ok") is not True
            or type(value.get("root_artifact_residue")) is not bool
            or not (empty or migratable or active_runtime)
            or value.get("release_id") != release_id
            or value.get("root_files") != root_files
        ):
            raise ReleaseError("deny-safe broker inventory reports root residue or skew")
        return value

    def _assert_switch_quiescent(
        self,
        *,
        broker_inventory: bool = True,
        allow_root_artifact_residue: bool = False,
        deadline_monotonic_ns: int | None = None,
    ) -> dict[str, object]:
        """Refuse release skew while any user/root runtime can still execute it."""
        if deadline_monotonic_ns is None:
            deadline_monotonic_ns = (
                time.monotonic_ns() + int(self.switch_timeout * 1_000_000_000)
            )
        inventory_budget = _SwitchInventoryBudget(deadline_monotonic_ns)
        inventory_budget.check("quiescence inventory")
        layout = self.layout
        self._recover_runner_scopes(deadline_monotonic_ns)
        _verify_dir(
            layout.runner_scope_root,
            0o700,
            layout.root_uid,
            layout.root_gid,
        )
        try:
            with os.scandir(layout.runner_scope_root) as entries:
                runner_records: list[str] = []
                for entry in entries:
                    inventory_budget.consume_entry(
                        "installer runner authority inventory"
                    )
                    runner_records.append(entry.name)
                    if len(runner_records) > MAX_SWITCH_INVENTORY_ENTRIES:
                        raise ReleaseError(
                            "installer runner authority inventory exceeds its bound"
                        )
        except OSError as exc:
            raise ReleaseError(
                "cannot inspect installer runner authority inventory"
            ) from exc
        if runner_records:
            raise ReleaseError(
                "active or uncertain installer runner authority remains"
            )
        if _present(layout.broker_ledger):
            raw, _ = _read_regular(
                layout.broker_ledger,
                uid=layout.root_uid,
                gid=layout.root_gid,
                mode=0o600,
                maximum=1024 * 1024,
            )
            phase = "unknown"
            try:
                value = json.loads(raw)
                if isinstance(value, dict) and isinstance(value.get("phase"), str):
                    phase = value["phase"]
            except (UnicodeDecodeError, ValueError):
                phase = "invalid"
            raise ReleaseError(
                f"broker ledger is present (phase={phase}); recover/stop before release switching"
            )

        if _present(layout.recovery_fence):
            _read_regular(
                layout.recovery_fence,
                uid=layout.target_uid,
                gid=layout.target_gid,
                mode=0o600,
                maximum=65_536,
            )
            raise ReleaseError(
                "multi-session recovery fence is present; recover/stop before release switching"
            )
        if _present(layout.supervisor_socket):
            info = layout.supervisor_socket.lstat()
            if info.st_uid != layout.target_uid:
                raise ReleaseError("unsafe multi-session supervisor socket owner")
            raise ReleaseError(
                "multi-session supervisor socket is present; stop before release switching"
            )
        if _present(layout.supervisor_ready):
            _read_regular(
                layout.supervisor_ready,
                uid=layout.target_uid,
                gid=layout.target_gid,
                mode=0o600,
                maximum=65_536,
            )
            raise ReleaseError(
                "multi-session supervisor readiness record is present; recover before release switching"
            )
        if _present(layout.multi_control):
            _verify_dir(
                layout.multi_control,
                0o700,
                layout.target_uid,
                layout.target_gid,
            )
            fault_markers: list[str] = []
            try:
                with os.scandir(layout.multi_control) as entries:
                    for entry in entries:
                        inventory_budget.consume_entry(
                            "multi-session control inventory"
                        )
                        if re.fullmatch(
                            r"qualification-fault-[0-9a-f]{64}\.json",
                            entry.name,
                        ):
                            fault_markers.append(entry.name)
            except OSError as exc:
                raise ReleaseError(
                    "cannot inspect multi-session control inventory"
                ) from exc
            if fault_markers:
                raise ReleaseError("qualification fault replay marker is present")
        for residue_root, label in (
            (layout.provider_root, "provider workspace"),
            (layout.qualify_root, "qualification workspace"),
            (layout.intent_root, "effect intent"),
            (layout.leader_root, "leader"),
            *((path, "recovery record") for path in layout.recovery_record_roots),
        ):
            if not _present(residue_root):
                continue
            _verify_dir(
                residue_root,
                0o700,
                layout.target_uid,
                layout.target_gid,
            )
            try:
                with os.scandir(residue_root) as entries:
                    first = next(entries, None)
                has_epoch = first is not None
                if has_epoch:
                    inventory_budget.consume_entry(
                        f"multi-session {label} inventory"
                    )
            except OSError as exc:
                raise ReleaseError(f"cannot inspect multi-session {label}") from exc
            if has_epoch:
                raise ReleaseError(
                    f"multi-session {label} is present; recover before release switching"
                )
        broker = (
            self._broker_inventory(
                allow_root_artifact_residue=allow_root_artifact_residue,
                deadline_monotonic_ns=deadline_monotonic_ns,
                inventory_budget=inventory_budget,
            )
            if broker_inventory
            else {"status": "validated-before-exclusive-selection-lock"}
        )
        inventory_budget.check("post-broker quiescence inventory")
        legacy_openvpn = self._legacy_openvpn_process_inventory(inventory_budget)
        if legacy_openvpn:
            raise ReleaseError(
                "legacy OpenVPN processes remain: "
                + ",".join(str(pid) for pid in legacy_openvpn)
            )
        processes = self._release_bound_process_inventory(inventory_budget)
        if processes:
            raise ReleaseError(
                "release-bound processes remain: "
                + ",".join(str(record["pid"]) for record in processes)
            )
        listeners = self._fixed_listener_inventory(inventory_budget)
        if listeners:
            raise ReleaseError(
                "fixed Grok listener residue remains: "
                + ",".join(str(record["port"]) for record in listeners)
            )
        cgroups = self._fixed_cgroup_inventory(inventory_budget)
        if cgroups:
            raise ReleaseError("Grok cgroup-v2 residue remains: " + ",".join(cgroups))
        inventory_budget.check("quiescence inventory completion")
        return {
            "broker": broker,
            "cgroups": cgroups,
            "listeners": listeners,
            "legacy_openvpn_processes": legacy_openvpn,
            "release_processes": processes,
        }

    def _publish_selection(
        self,
        release_id: str,
        operation: str,
        *,
        evidence_sha256: str,
        selection_phase: str,
        fault_at: str | None,
        selector_faults: bool,
        qualified_rungs: Iterable[Mapping[str, object]] = (),
    ) -> None:
        layout = self.layout
        target_root_files = self._target_root_files(release_id)
        deny = self._deny_record()
        if deny is not None:
            self._converge_deny_release_access(deny)
        else:
            exposed = {release_id}
            current = self.active_release_id()
            if current is not None:
                exposed.add(current)
            self._converge_release_access(exposed)
        entrypoint_bytes = self._gate_source(
            release_id, "user", target_root_files=target_root_files
        )
        broker_bytes = self._gate_source(
            release_id, "broker", target_root_files=target_root_files
        )
        user_record, root_record = self._selection_records(
            release_id,
            operation,
            entrypoint_bytes,
            broker_bytes,
            target_root_files=target_root_files,
            evidence_sha256=evidence_sha256,
            selection_phase=selection_phase,
            qualified_rungs=qualified_rungs,
        )

        _atomic_symlink(
            layout.root_current,
            f"releases/{release_id}",
            uid=layout.root_uid,
            gid=layout.root_gid,
            parent_mode=0o755,
        )
        if selector_faults:
            self._fault(fault_at, AFTER_ROOT_SELECTOR)
        _atomic_symlink(
            layout.current,
            f"releases/{release_id}",
            uid=layout.root_uid,
            gid=layout.root_gid,
            parent_mode=0o755,
        )
        if deny is not None:
            self._converge_deny_release_access(deny)
        if selector_faults:
            self._fault(fault_at, AFTER_CURRENT_SELECTOR)
        _atomic_write(
            layout.broker_entrypoint,
            broker_bytes,
            mode=0o555,
            uid=layout.root_uid,
            gid=layout.root_gid,
            parent_mode=0o755,
            allow_selector_replacement=True,
        )
        if selector_faults:
            self._fault(fault_at, AFTER_BROKER_SELECTOR)
        _atomic_write(
            layout.entrypoint,
            entrypoint_bytes,
            mode=0o555,
            uid=layout.root_uid,
            gid=layout.root_gid,
            parent_mode=0o755,
            parent_uid=layout.target_uid,
            parent_gid=layout.target_gid,
            replace_owners=frozenset(
                {
                    (layout.root_uid, layout.root_gid),
                    (layout.target_uid, layout.target_gid),
                }
            ),
            allow_selector_replacement=True,
        )
        if selector_faults:
            self._fault(fault_at, AFTER_ENTRYPOINT_SELECTOR)
        _atomic_json(
            layout.selected,
            user_record,
            mode=0o444,
            uid=layout.target_uid,
            gid=layout.target_gid,
            parent_mode=0o700,
        )
        if selector_faults:
            self._fault(fault_at, AFTER_USER_SELECTION_METADATA)
        _atomic_json(
            layout.root_selected,
            root_record,
            mode=0o444,
            uid=layout.root_uid,
            gid=layout.root_gid,
            parent_mode=0o755,
        )
        if selector_faults:
            self._fault(fault_at, AFTER_SELECTION_METADATA)
        self._converge_release_access(release_id)
        if not self._selection_is_exact(
            release_id,
            permit_deny=True,
            expected_phase=selection_phase,
        ):
            raise ReleaseError("new root/user selection is not coherent")

    def _complete_promoted_selection(
        self,
        release_id: str,
        operation: str,
        fault_at: str | None,
        *,
        allow_legacy_residue: bool = False,
        qualified_rungs: Iterable[Mapping[str, object]] = (),
    ) -> None:
        self._assert_switch_quiescent(
            allow_root_artifact_residue=allow_legacy_residue
        )
        with self._selection_locked(self.switch_timeout):
            self._assert_switch_quiescent(broker_inventory=False)
            self._publish_selection(
                release_id,
                operation,
                evidence_sha256=ZERO_DIGEST,
                selection_phase="CANARY",
                fault_at=fault_at,
                selector_faults=True,
            )
        self._fault(fault_at, AFTER_CANARY_SELECTION)

        legacy_migration: Mapping[str, object]
        if operation == "install":
            legacy_migration = self._bootstrap_legacy_migration(release_id)
        else:
            legacy_migration = {
                "operation": "not-required",
                "release_id": release_id,
            }
        evidence = self._produce_evidence(
            release_id,
            operation,
            legacy_migration,
        )
        evidence_sha256 = self._write_evidence(evidence)
        self._fault(fault_at, AFTER_EVIDENCE)
        validated_digest = self._validate_evidence(release_id, operation)
        if validated_digest != evidence_sha256:
            raise ReleaseError("published promotion evidence changed during validation")

        self._assert_switch_quiescent()
        with self._selection_locked(self.switch_timeout):
            self._assert_switch_quiescent(broker_inventory=False)
            self._publish_selection(
                release_id,
                operation,
                evidence_sha256=evidence_sha256,
                selection_phase="READY",
                fault_at=None,
                selector_faults=False,
                qualified_rungs=qualified_rungs,
            )
            self._fault(fault_at, AFTER_FINAL_SELECTION)
            if not self._selection_is_exact(release_id, permit_deny=True):
                raise ReleaseError("final evidence-bound selection is not coherent")
            self._fault(fault_at, BEFORE_DENY_CLEAR)
            self._clear_deny()
        self._fault(fault_at, AFTER_DENY_CLEAR)

    def _promote_or_restore(
        self,
        release_id: str,
        operation: str,
        fault_at: str | None,
        from_release: str | None,
    ) -> None:
        try:
            self._complete_promoted_selection(
                release_id,
                operation,
                fault_at,
                # A first install or A->B upgrade can inherit the compatibility
                # singleton tree.  Same-release repair and rollback retain the
                # ordinary strict-empty precondition.  The broker independently
                # validates any non-null prior release's passing root evidence.
                allow_legacy_residue=(
                    operation == "install" and from_release != release_id
                ),
            )
            return
        except InjectedFault:
            # Fault injection models process loss: preserve the exact durable
            # intermediate state for a later explicit resume.
            raise
        except (ReleaseError, OSError, subprocess.SubprocessError) as exc:
            target_error = (
                exc
                if isinstance(exc, ReleaseError)
                else ReleaseError(f"target promotion system failure: {exc}")
            )
            if from_release is None or from_release == release_id:
                if isinstance(exc, ReleaseError):
                    raise
                raise target_error from exc
            try:
                self.validate_target_release_pair(from_release)
                self._complete_promoted_selection(from_release, "rollback", None)
            except (ReleaseError, OSError, subprocess.SubprocessError) as restore_exc:
                restore_error = (
                    restore_exc
                    if isinstance(restore_exc, ReleaseError)
                    else ReleaseError(f"rollback promotion system failure: {restore_exc}")
                )
                raise ReleaseError(
                    "target promotion failed and rollback smoke could not be proved; "
                    f"durable deny remains: target={target_error}; rollback={restore_error}"
                ) from restore_exc
            raise ReleaseError(
                f"target promotion failed; previous release was restored: {target_error}"
            ) from target_error

    def _validate_rung_canary_value(self, value: object) -> dict[str, object]:
        fields = {
            "schema_version", "release_id", "host_id", "rung", "route_profile",
            "contract_sha256", "grok_release_id", "model_id", "canary_kind",
            "canary_nonce", "created_unix_ns",
        }
        if not isinstance(value, dict):
            raise ReleaseError("rung canary authorization record is invalid")
        canary_kind = value.get("canary_kind")
        contract = value.get("contract_sha256")
        if (
            set(value) != fields
            or value.get("schema_version") != RUNG_CANARY_SCHEMA_VERSION
            or type(value.get("release_id")) is not str
            or RELEASE_ID_RE.fullmatch(str(value.get("release_id"))) is None
            or value.get("host_id") != self._host_id()
            or type(value.get("rung")) is not str
            or RUNG_TOKEN_RE.fullmatch(str(value.get("rung"))) is None
            or not _route_profile_matches_rung(
                value.get("route_profile"), value.get("rung")
            )
            or canary_kind not in {"release", "rung"}
            or not (
                (canary_kind == "release" and contract is None)
                or (
                    canary_kind == "rung"
                    and type(contract) is str
                    and RELEASE_ID_RE.fullmatch(contract) is not None
                )
            )
            or type(value.get("grok_release_id")) is not str
            or GROK_RELEASE_RE.fullmatch(str(value.get("grok_release_id"))) is None
            or type(value.get("model_id")) is not str
            or MODEL_ID_RE.fullmatch(str(value.get("model_id"))) is None
            or (canary_kind == "release" and value.get("rung") != "direct")
            or (canary_kind == "release" and value.get("route_profile") != "direct")
            or (canary_kind == "release" and value.get("model_id") != QUALIFICATION_FAKE_MODEL)
            or type(value.get("canary_nonce")) is not str
            or RELEASE_ID_RE.fullmatch(str(value.get("canary_nonce"))) is None
            or type(value.get("created_unix_ns")) is not int
            or value.get("created_unix_ns", 0) <= 0
        ):
            raise ReleaseError("rung canary authorization record is invalid")
        return value

    def _read_rung_canary(self) -> dict[str, object]:
        value = self._read_json(
            self.layout.rung_canary,
            uid=self.layout.root_uid,
            gid=self.layout.root_gid,
            mode=0o444,
        )
        return self._validate_rung_canary_value(value)

    def _qualification_fake_identity(self, release_id: str) -> str:
        raw, _mode = _read_regular(
            self.layout.user_releases
            / release_id
            / "grok_ms"
            / "qualification_fake_grok.py",
            uid=self.layout.root_uid,
            gid=self.layout.root_gid,
            mode=0o555,
            maximum=1024 * 1024,
        )
        return "sha256:" + _sha256_bytes(raw)

    def _canary_environment(
        self,
        descriptor: int,
        record: Mapping[str, object],
    ) -> dict[str, str]:
        environment = {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": str(self.layout.user_root.parents[2]),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "GROK_MULTI_SESSION": "1",
            "GROK_RELEASE_CANARY_MODE": "1",
            "GROK_RELEASE_CANARY_FD": str(descriptor),
            "GROK_RELEASE_CANARY_RELEASE_ID": str(record["release_id"]),
            "GROK_RELEASE_RUNG_CANARY": "1",
            "GROK_RELEASE_CANARY_KIND": str(record["canary_kind"]),
            "GROK_RELEASE_CANARY_RUNG": str(record["rung"]),
            "GROK_RELEASE_CANARY_ROUTE_PROFILE": str(record["route_profile"]),
            "GROK_RELEASE_CANARY_GROK_RELEASE": str(record["grok_release_id"]),
            "GROK_RELEASE_CANARY_MODEL": str(record["model_id"]),
            "GROK_RELEASE_CANARY_NONCE": str(record["canary_nonce"]),
        }
        contract = record.get("contract_sha256")
        if contract is not None:
            environment["GROK_RELEASE_CANARY_CONTRACT"] = str(contract)
        if self.layout.test_install:
            environment.update(
                {
                    "GROK_TESTING": "1",
                    "GROK_TEST_ROOT_RELEASE_CONTROL": str(self.layout.root_control),
                }
            )
            for name in CANARY_TEST_ENV:
                value = os.environ.get(name)
                if value is not None:
                    environment[name] = value
        return environment

    def _qualification_fault_marker(self, record: Mapping[str, object]) -> Path:
        nonce = str(record.get("canary_nonce", ""))
        if RELEASE_ID_RE.fullmatch(nonce) is None:
            raise ReleaseError("qualification fault marker nonce is invalid")
        return self.layout.multi_control / f"qualification-fault-{nonce}.json"

    def _remove_qualification_fault_marker(
        self,
        record: Mapping[str, object],
    ) -> None:
        path = self._qualification_fault_marker(record)
        if not _present(path):
            return
        _read_regular(
            path,
            uid=self.layout.target_uid,
            gid=self.layout.target_gid,
            mode=0o600,
            maximum=65_536,
        )
        path.unlink()
        _fsync_dir(path.parent)

    def _remove_partial_release_qualification(
        self,
        record: Mapping[str, object],
    ) -> None:
        if record.get("canary_kind") != "release":
            return
        release_id = str(record["release_id"])
        if _present(self.layout.qualification_state_path(release_id)):
            # A completed state is durable release evidence and is never
            # removed merely because terminal canary cleanup was interrupted.
            return
        root = self.layout.qualification_release_dir(release_id)
        if not _present(root):
            return
        _verify_dir(root, 0o755, self.layout.root_uid, self.layout.root_gid)
        allowed = {
            *(f"{step}.json" for step in QUALIFICATION_STEPS),
            *(f"pending-qualification-{step}.json" for step in QUALIFICATION_STEPS),
        }
        for path in sorted(root.iterdir(), key=lambda item: item.name):
            if path.name not in allowed:
                raise ReleaseError("release qualification directory contains unknown residue")
            if path.name.startswith("pending-") and self._pending_record_is_active(
                path, recovery=True
            ):
                raise ReleaseError("cannot remove an active release qualification")
        for path in sorted(root.iterdir(), key=lambda item: item.name):
            path.unlink()
        _fsync_dir(root)

    def _remove_rung_canary(self) -> None:
        if not _present(self.layout.rung_canary):
            return
        record = self._read_rung_canary()
        run_root = self.layout.rung_transcript_dir(
            str(record["release_id"]), str(record["canary_nonce"])
        )
        _verify_dir(run_root, 0o755, self.layout.root_uid, self.layout.root_gid)
        pending_paths: list[Path] = []
        qualification_pending = False
        for path in sorted(run_root.iterdir(), key=lambda item: item.name):
            if (
                PENDING_RUN_RE.fullmatch(path.name) is not None
                or path.name == "pending-qualification-real-pair.json"
            ):
                pending_paths.append(path)
                qualification_pending = (
                    qualification_pending
                    or path.name == "pending-qualification-real-pair.json"
                )
                continue
            if path.name == "real-pair.json":
                continue
            if (
                path.name.endswith(".json")
                and RELEASE_ID_RE.fullmatch(path.name[:-5]) is not None
            ):
                continue
            raise ReleaseError("rung transcript directory contains unknown abort residue")
        for pending_path in pending_paths:
            if self._pending_record_is_active(pending_path, recovery=True):
                raise ReleaseError("cannot remove an active rung canary execution")
        for pending_path in pending_paths:
            pending_path.unlink()
        if qualification_pending:
            real_pair = run_root / "real-pair.json"
            if _present(real_pair):
                _read_regular(
                    real_pair,
                    uid=self.layout.root_uid,
                    gid=self.layout.root_gid,
                    mode=0o444,
                    maximum=1024 * 1024,
                )
                real_pair.unlink()
        if pending_paths:
            _fsync_dir(run_root)
        self._remove_qualification_fault_marker(record)
        self._remove_partial_release_qualification(record)
        self.layout.rung_canary.unlink()
        _fsync_dir(self.layout.root_control)

    def _selection_digests(self) -> tuple[str, str]:
        user_raw, _mode = _read_regular(
            self.layout.selected,
            uid=self.layout.target_uid,
            gid=self.layout.target_gid,
            mode=0o444,
            maximum=1024 * 1024,
        )
        root_raw, _mode = _read_regular(
            self.layout.root_selected,
            uid=self.layout.root_uid,
            gid=self.layout.root_gid,
            mode=0o444,
            maximum=1024 * 1024,
        )
        return _sha256_bytes(user_raw), _sha256_bytes(root_raw)

    def _selected_gate_digests(self, release_id: str) -> dict[str, str]:
        if RELEASE_ID_RE.fullmatch(release_id) is None:
            raise ReleaseError("gate digest release ID is invalid")
        root_record = self._read_json(
            self.layout.root_selected,
            uid=self.layout.root_uid,
            gid=self.layout.root_gid,
            mode=0o444,
        )
        entrypoint_raw, _mode = _read_regular(
            self.layout.entrypoint,
            uid=self.layout.root_uid,
            gid=self.layout.root_gid,
            mode=0o555,
        )
        broker_raw, _mode = _read_regular(
            self.layout.broker_entrypoint,
            uid=self.layout.root_uid,
            gid=self.layout.root_gid,
            mode=0o555,
        )
        digests = {
            "entrypoint_sha256": _sha256_bytes(entrypoint_raw),
            "broker_gate_sha256": _sha256_bytes(broker_raw),
        }
        if (
            root_record.get("release_id") != release_id
            or root_record.get("entrypoint_sha256") != digests["entrypoint_sha256"]
            or root_record.get("broker_gate_sha256") != digests["broker_gate_sha256"]
        ):
            raise ReleaseError("selected gate identity is incoherent")
        return digests

    def _validate_canary_terminal_value(self, value: object) -> dict[str, object]:
        fields = {
            "schema_version",
            "kind",
            "disposition",
            "release_id",
            "host_id",
            "canary",
            "user_selection_sha256",
            "root_selection_sha256",
            "prepared_unix_ns",
        }
        if not isinstance(value, dict) or set(value) != fields:
            raise ReleaseError("canary terminal record has an unexpected shape")
        canary = self._validate_rung_canary_value(value.get("canary"))
        if (
            value.get("schema_version") != CANARY_TERMINAL_SCHEMA_VERSION
            or value.get("kind") != "canary-terminal"
            or value.get("disposition")
            not in {"abort", "release-qualified", "rung-promoted"}
            or value.get("release_id") != canary.get("release_id")
            or value.get("host_id") != self._host_id()
            or value.get("host_id") != canary.get("host_id")
            or type(value.get("user_selection_sha256")) is not str
            or RELEASE_ID_RE.fullmatch(str(value.get("user_selection_sha256")))
            is None
            or type(value.get("root_selection_sha256")) is not str
            or RELEASE_ID_RE.fullmatch(str(value.get("root_selection_sha256")))
            is None
            or type(value.get("prepared_unix_ns")) is not int
            or value.get("prepared_unix_ns", 0) <= 0
            or (
                value.get("disposition") == "release-qualified"
                and canary.get("canary_kind") != "release"
            )
            or (
                value.get("disposition") == "rung-promoted"
                and canary.get("canary_kind") != "rung"
            )
        ):
            raise ReleaseError("canary terminal record is invalid or mismatched")
        return value

    def _read_canary_terminal(self) -> dict[str, object]:
        value = self._read_json(
            self.layout.canary_terminal,
            uid=self.layout.root_uid,
            gid=self.layout.root_gid,
            mode=0o444,
        )
        return self._validate_canary_terminal_value(value)

    def _prepare_canary_terminal(
        self,
        canary: Mapping[str, object],
        disposition: str,
    ) -> dict[str, object]:
        exact_canary = self._validate_rung_canary_value(dict(canary))
        release_id = str(exact_canary["release_id"])
        if not self._selection_is_exact(release_id, permit_deny=True):
            raise ReleaseError("canary terminal selection is not coherent")
        user_digest, root_digest = self._selection_digests()
        proposed = {
            "schema_version": CANARY_TERMINAL_SCHEMA_VERSION,
            "kind": "canary-terminal",
            "disposition": disposition,
            "release_id": release_id,
            "host_id": self._host_id(),
            "canary": exact_canary,
            "user_selection_sha256": user_digest,
            "root_selection_sha256": root_digest,
            "prepared_unix_ns": time.time_ns(),
        }
        self._validate_canary_terminal_value(proposed)
        if _present(self.layout.canary_terminal):
            existing = self._read_canary_terminal()
            comparable = dict(existing)
            comparable.pop("prepared_unix_ns", None)
            expected = dict(proposed)
            expected.pop("prepared_unix_ns", None)
            if comparable != expected:
                raise ReleaseError("a different canary terminal record already exists")
            return existing
        _atomic_json(
            self.layout.canary_terminal,
            proposed,
            mode=0o444,
            uid=self.layout.root_uid,
            gid=self.layout.root_gid,
            parent_mode=0o755,
        )
        return self._read_canary_terminal()

    def _assert_terminal_canary_residue(
        self,
        canary: Mapping[str, object],
    ) -> None:
        release_id = str(canary["release_id"])
        nonce = str(canary["canary_nonce"])
        release_root = self.layout.rung_transcript_root / release_id
        run_root = self.layout.rung_transcript_dir(release_id, nonce)
        _verify_dir(
            self.layout.rung_transcript_root,
            0o755,
            self.layout.root_uid,
            self.layout.root_gid,
        )
        _verify_dir(release_root, 0o755, self.layout.root_uid, self.layout.root_gid)
        _verify_dir(run_root, 0o755, self.layout.root_uid, self.layout.root_gid)
        nonce_roots = sorted(release_root.iterdir(), key=lambda item: item.name)
        if len(nonce_roots) > 256:
            raise ReleaseError("rung transcript nonce inventory exceeds its bound")
        for candidate in nonce_roots:
            if RELEASE_ID_RE.fullmatch(candidate.name) is None:
                raise ReleaseError("rung transcript nonce inventory is invalid")
            _verify_dir(candidate, 0o755, self.layout.root_uid, self.layout.root_gid)
            entries = sorted(candidate.iterdir(), key=lambda item: item.name)
            if len(entries) > 67:
                raise ReleaseError("rung transcript inventory exceeds its bound")
            if any(
                PENDING_RUN_RE.fullmatch(path.name) is not None
                or QUALIFICATION_PENDING_RE.fullmatch(path.name) is not None
                for path in entries
            ):
                raise ReleaseError("stale canary execution intent remains")

        entries = sorted(path.name for path in run_root.iterdir())
        if canary.get("canary_kind") == "release":
            if entries:
                raise ReleaseError("release terminal transcript contains residue")
        else:
            if any(
                name != "real-pair.json"
                and re.fullmatch(r"[0-9a-f]{64}\.json", name) is None
                for name in entries
            ):
                raise ReleaseError("rung terminal transcript contains residue")
            self._rung_transcript_digests(
                release_id=release_id,
                nonce=nonce,
                rung=str(canary["rung"]),
                contract_sha256=str(canary["contract_sha256"]),
                grok_release_id=str(canary["grok_release_id"]),
                require_success=False,
            )
            real_pair = self.layout.rung_qualification_path(release_id, nonce)
            if _present(real_pair):
                self._read_qualification_result(
                    real_pair,
                    step="real-pair",
                    canary=canary,
                )
        if _present(self._qualification_fault_marker(canary)):
            raise ReleaseError("qualification fault replay marker remains")

    def _converge_canary_terminal(self, *, fault_at: str | None = None) -> InstallResult:
        if fault_at not in {None, AFTER_CANARY_UNLINK, AFTER_DENY_CLEAR}:
            raise ReleaseError("unknown canary terminal fault stage")
        terminal = self._read_canary_terminal()
        canary = terminal["canary"]
        assert isinstance(canary, dict)
        release_id = str(terminal["release_id"])
        deny = self._deny_record()
        if deny is not None and (
            deny.get("operation") != "canary"
            or deny.get("from_release") != release_id
            or deny.get("to_release") != release_id
        ):
            raise ReleaseError("canary terminal deny ledger is mismatched")
        if _present(self.layout.rung_canary):
            if self._read_rung_canary() != canary:
                raise ReleaseError("canary terminal authorization changed")
            self._remove_rung_canary()
        self._fault(fault_at, AFTER_CANARY_UNLINK)
        if _present(self.layout.rung_canary):
            raise ReleaseError("canary terminal authorization remains")
        self._converge_release_access(release_id)
        if not self._selection_is_exact(release_id, permit_deny=deny is not None):
            raise ReleaseError("canary terminal selection is not coherent")
        if self._selection_digests() != (
            terminal["user_selection_sha256"],
            terminal["root_selection_sha256"],
        ):
            raise ReleaseError("canary terminal selection digest changed")
        self._assert_switch_quiescent()
        self._assert_terminal_canary_residue(canary)
        self._clear_deny()
        self._fault(fault_at, AFTER_DENY_CLEAR)
        # The terminal record deliberately outlives durable deny clearance.  A
        # crash here leaves normal admission coherent and the same convergence
        # path can safely garbage-collect the exact closed record.
        if self._selection_digests() != (
            terminal["user_selection_sha256"],
            terminal["root_selection_sha256"],
        ):
            raise ReleaseError("canary terminal selection changed during clearance")
        self.layout.canary_terminal.unlink()
        _fsync_dir(self.layout.root_control)
        return InstallResult(release_id, True, str(terminal["disposition"]))

    def _finish_canary_terminal(
        self,
        canary: Mapping[str, object],
        disposition: str,
        *,
        fault_at: str | None = None,
    ) -> InstallResult:
        self._prepare_canary_terminal(canary, disposition)
        return self._converge_canary_terminal(fault_at=fault_at)

    def begin_rung_canary(
        self,
        *,
        release_id: str,
        rung: str,
        route_profile: str,
        contract_sha256: str,
        grok_release_id: str,
        model_id: str = QUALIFICATION_FAKE_MODEL,
    ) -> InstallResult:
        if RELEASE_ID_RE.fullmatch(release_id) is None:
            raise ReleaseError("rung canary release ID is invalid")
        if RUNG_TOKEN_RE.fullmatch(rung) is None:
            raise ReleaseError("rung canary name is invalid")
        if not _route_profile_matches_rung(route_profile, rung):
            raise ReleaseError("rung canary route profile does not authorize the rung")
        if RELEASE_ID_RE.fullmatch(contract_sha256) is None:
            raise ReleaseError("rung canary contract digest is invalid")
        if GROK_RELEASE_RE.fullmatch(grok_release_id) is None:
            raise ReleaseError("rung canary Grok release identity is invalid")
        if MODEL_ID_RE.fullmatch(model_id) is None:
            raise ReleaseError("rung canary model identity is invalid")
        with self._locked():
            if _present(self.layout.canary_terminal):
                self._converge_canary_terminal()
            if not _present(self.layout.rollback_deny):
                if not self._selection_is_exact(release_id):
                    raise ReleaseError("rung canary requires the exact active READY release")
                snapshot = self._assert_switch_quiescent()
                with self._selection_locked(self.switch_timeout):
                    if not self._selection_is_exact(release_id):
                        raise ReleaseError(
                            "rung canary selection changed before fencing"
                        )
                    locked_snapshot = self._assert_switch_quiescent(
                        broker_inventory=False
                    )
                    locked_snapshot["broker"] = snapshot["broker"]
                    self._write_boot_inventory(release_id, locked_snapshot)
                    self._publish_deny("canary", release_id, release_id)
            deny = self._deny_record()
            if (
                deny is None
                or deny.get("operation") != "canary"
                or deny.get("from_release") != release_id
                or deny.get("to_release") != release_id
            ):
                raise ReleaseError("another interrupted operation is already fenced")
            record = {
                "schema_version": RUNG_CANARY_SCHEMA_VERSION,
                "release_id": release_id,
                "host_id": self._host_id(),
                "rung": rung,
                "route_profile": route_profile,
                "contract_sha256": contract_sha256,
                "grok_release_id": grok_release_id,
                "model_id": model_id,
                "canary_kind": "rung",
                "canary_nonce": secrets.token_hex(32),
                "created_unix_ns": time.time_ns(),
            }
            if _present(self.layout.rung_canary):
                existing = self._read_rung_canary()
                comparable = dict(existing)
                comparable.pop("created_unix_ns", None)
                comparable.pop("canary_nonce", None)
                expected = dict(record)
                expected.pop("created_unix_ns", None)
                expected.pop("canary_nonce", None)
                if comparable != expected:
                    raise ReleaseError("a different rung canary is already authorized")
                release_root = self.layout.rung_transcript_root / release_id
                _ensure_dir(
                    release_root,
                    0o755,
                    self.layout.root_uid,
                    self.layout.root_gid,
                )
                _ensure_dir(
                    self.layout.rung_transcript_dir(
                        release_id, str(existing["canary_nonce"])
                    ),
                    0o755,
                    self.layout.root_uid,
                    self.layout.root_gid,
                )
                if self._pending_rung_executions(
                    release_id=release_id,
                    nonce=str(existing["canary_nonce"]),
                    rung=rung,
                    contract_sha256=contract_sha256,
                    grok_release_id=grok_release_id,
                ):
                    raise ReleaseError("rung canary has a crash-pending execution")
                return InstallResult(release_id, False, "begin-rung-canary")
            _atomic_json(
                self.layout.rung_canary,
                record,
                mode=0o444,
                uid=self.layout.root_uid,
                gid=self.layout.root_gid,
                parent_mode=0o755,
            )
            release_root = self.layout.rung_transcript_root / release_id
            _ensure_dir(
                release_root,
                0o755,
                self.layout.root_uid,
                self.layout.root_gid,
            )
            _ensure_dir(
                self.layout.rung_transcript_dir(
                    release_id, str(record["canary_nonce"])
                ),
                0o755,
                self.layout.root_uid,
                self.layout.root_gid,
            )
            return InstallResult(release_id, True, "begin-rung-canary")

    def begin_release_qualification(self, *, release_id: str) -> InstallResult:
        if RELEASE_ID_RE.fullmatch(release_id) is None:
            raise ReleaseError("release qualification release ID is invalid")
        with self._locked():
            if _present(self.layout.canary_terminal):
                terminal = self._read_canary_terminal()
                if (
                    terminal.get("release_id") != release_id
                    or terminal.get("disposition") != "release-qualified"
                ):
                    raise ReleaseError(
                        "a different canary terminal operation requires recovery"
                    )
                self._converge_canary_terminal()
            if _present(self.layout.qualification_state_path(release_id)):
                self._validate_release_qualification(release_id)
                return InstallResult(release_id, False, "begin-release-qualification")
            if not _present(self.layout.rollback_deny):
                if not self._selection_is_exact(release_id):
                    raise ReleaseError(
                        "release qualification requires the exact active READY release"
                    )
                snapshot = self._assert_switch_quiescent()
                with self._selection_locked(self.switch_timeout):
                    if not self._selection_is_exact(release_id):
                        raise ReleaseError(
                            "release qualification selection changed before fencing"
                        )
                    locked_snapshot = self._assert_switch_quiescent(
                        broker_inventory=False
                    )
                    locked_snapshot["broker"] = snapshot["broker"]
                    self._write_boot_inventory(release_id, locked_snapshot)
                    self._publish_deny("canary", release_id, release_id)
            deny = self._deny_record()
            if (
                deny is None
                or deny.get("operation") != "canary"
                or deny.get("from_release") != release_id
                or deny.get("to_release") != release_id
            ):
                raise ReleaseError("another interrupted operation is already fenced")
            record = {
                "schema_version": RUNG_CANARY_SCHEMA_VERSION,
                "release_id": release_id,
                "host_id": self._host_id(),
                "rung": "direct",
                "route_profile": "direct",
                "contract_sha256": None,
                "grok_release_id": self._qualification_fake_identity(release_id),
                "model_id": QUALIFICATION_FAKE_MODEL,
                "canary_kind": "release",
                "canary_nonce": secrets.token_hex(32),
                "created_unix_ns": time.time_ns(),
            }
            if _present(self.layout.rung_canary):
                existing = self._read_rung_canary()
                comparable = dict(existing)
                comparable.pop("created_unix_ns", None)
                comparable.pop("canary_nonce", None)
                expected = dict(record)
                expected.pop("created_unix_ns", None)
                expected.pop("canary_nonce", None)
                if comparable != expected:
                    raise ReleaseError("a different canary is already authorized")
                return InstallResult(release_id, False, "begin-release-qualification")
            _atomic_json(
                self.layout.rung_canary,
                record,
                mode=0o444,
                uid=self.layout.root_uid,
                gid=self.layout.root_gid,
                parent_mode=0o755,
            )
            release_root = self.layout.rung_transcript_root / release_id
            _ensure_dir(release_root, 0o755, self.layout.root_uid, self.layout.root_gid)
            _ensure_dir(
                self.layout.rung_transcript_dir(
                    release_id, str(record["canary_nonce"])
                ),
                0o755,
                self.layout.root_uid,
                self.layout.root_gid,
            )
            _ensure_dir(
                self.layout.qualification_release_dir(release_id),
                0o755,
                self.layout.root_uid,
                self.layout.root_gid,
            )
            return InstallResult(release_id, True, "begin-release-qualification")

    def _validate_qualification_result_value(
        self,
        value: object,
        *,
        step: str,
        canary: Mapping[str, object],
        require_pass: bool = True,
    ) -> dict[str, object]:
        if step not in QUALIFICATION_MODES:
            raise ReleaseError("qualification result step is invalid")
        if not isinstance(value, dict) or set(value) != QUALIFICATION_COMMON_FIELDS:
            raise ReleaseError("qualification result has an unexpected shape")
        observations = value.get("observations")
        status = value.get("status")
        error_code = value.get("error_code")
        error_sha256 = value.get("error_sha256")
        duration_ms = value.get("duration_ms")
        started = value.get("started_unix_ns")
        completed = value.get("completed_unix_ns")
        contract = value.get("contract_sha256")
        if (
            value.get("schema_version") != QUALIFICATION_RESULT_SCHEMA_VERSION
            or value.get("kind") != "grok-multi-session-qualification"
            or value.get("step") != step
            or value.get("release_id") != canary.get("release_id")
            or value.get("canary_nonce") != canary.get("canary_nonce")
            or value.get("canary_kind") != canary.get("canary_kind")
            or value.get("rung") != canary.get("rung")
            or value.get("route_profile") != canary.get("route_profile")
            or value.get("grok_release_id") != canary.get("grok_release_id")
            or value.get("model_id") != canary.get("model_id")
            or type(contract) is not str
            or RELEASE_ID_RE.fullmatch(contract) is None
            or (
                canary.get("contract_sha256") is not None
                and contract != canary.get("contract_sha256")
            )
            or status not in {"passed", "blocked", "failed"}
            or type(started) is not int
            or started <= 0
            or type(completed) is not int
            or completed < started
            or type(duration_ms) is not int
            or not 0 <= duration_ms <= 900_000
            or not isinstance(observations, dict)
            or set(observations) != QUALIFICATION_OBSERVATION_FIELDS[step]
            or (
                step in QUALIFICATION_STEPS
                and not _qualification_resource_shape_valid(observations)
            )
            or not (
                (status == "passed" and error_code is None and error_sha256 is None)
                or (
                    status == "failed"
                    and type(error_code) is str
                    and error_code in QUALIFICATION_FAILURE_CODES[step]
                    and type(error_sha256) is str
                    and RELEASE_ID_RE.fullmatch(error_sha256) is not None
                )
                or (
                    status == "blocked"
                    and type(error_code) is str
                    and error_code in QUALIFICATION_BLOCKED_CODES[step]
                    and type(error_sha256) is str
                    and RELEASE_ID_RE.fullmatch(error_sha256) is not None
                )
            )
            or (require_pass and status != "passed")
        ):
            raise ReleaseError("qualification result is failed or mismatched")

        digest = observations.get("detail_sha256")
        if type(digest) is not str or RELEASE_ID_RE.fullmatch(digest) is None:
            raise ReleaseError("qualification detail digest is invalid")
        if step == "load32":
            true_fields = {
                "shared_owner_epoch", "shared_generation", "shared_contract",
                "overload_rejected", "byte_path_verified", "host_limits_captured",
                "resource_gate_passed", "cleanup_proved",
            }
            valid = (
                observations.get("clients_requested") == 32
                and observations.get("clients_completed") == 32
                and observations.get("active_rung") == "direct"
                and observations.get("unique_leaders") == 32
                and all(observations.get(name) is True for name in true_fields)
                and type(observations.get("ready_duration_ms")) is int
                and 0 <= observations.get("ready_duration_ms", -1) <= 900_000
                and _qualification_resource_proves(step, observations)
            )
        elif step == "fault-recovery":
            true_fields = {
                "supervisor_loss_exact", "wrapper_failed_closed",
                "descendant_contained", "first_recovery_applied",
                "second_recovery_noop", "resource_gate_passed", "cleanup_proved",
            }
            valid = (
                observations.get("active_rung") == "direct"
                and all(observations.get(name) is True for name in true_fields)
                and type(observations.get("recovery_duration_ms")) is int
                and 0 <= observations.get("recovery_duration_ms", -1) <= 900_000
                and _qualification_resource_proves(step, observations)
            )
        else:
            true_fields = {
                "shared_owner_epoch", "shared_generation", "shared_contract",
                "shared_leader_disabled",
                "outputs_valid", "exit_codes_zero", "cache_before_valid",
                "cache_during_valid", "cache_after_valid", "cache_identity_safe",
                "provider_fault_authenticated", "single_repair_observed",
                "clients_survived_repair", "cleanup_proved",
            }
            valid = (
                observations.get("sessions_requested") == 2
                and observations.get("sessions_completed") == 2
                and observations.get("active_rung") == canary.get("rung")
                and observations.get("model_id") == canary.get("model_id")
                and observations.get("independent_grok_units") == 2
                and observations.get("leader_socket_count") == 0
                and observations.get("unique_session_ids") == 2
                and all(observations.get(name) is True for name in true_fields)
                and type(observations.get("reconnect_duration_ms")) is int
                and 0 <= observations.get("reconnect_duration_ms", -1) <= 900_000
                and type(observations.get("transport_duration_ms")) is int
                and 0 <= observations.get("transport_duration_ms", -1) <= 900_000
                and observations.get("blocked_reason") is None
            )
        if status == "passed" and not valid:
            raise ReleaseError("qualification result does not prove its fixed step")
        return value

    def _read_qualification_result(
        self,
        path: Path,
        *,
        step: str,
        canary: Mapping[str, object],
    ) -> tuple[dict[str, object], str]:
        raw, _mode = _read_regular(
            path,
            uid=self.layout.root_uid,
            gid=self.layout.root_gid,
            mode=0o444,
            maximum=1024 * 1024,
        )
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, ValueError) as exc:
            raise ReleaseError(f"cannot parse qualification result: {exc}") from exc
        if raw != _canonical_json(value) + b"\n":
            raise ReleaseError("qualification result is not canonical JSON")
        return self._validate_qualification_result_value(
            value, step=step, canary=canary
        ), _sha256_bytes(raw)

    def _validate_release_qualification(
        self,
        release_id: str,
    ) -> tuple[dict[str, object], str]:
        root = self.layout.qualification_release_dir(release_id)
        _verify_dir(root, 0o755, self.layout.root_uid, self.layout.root_gid)
        expected_entries = {"load32.json", "fault-recovery.json", "release.json"}
        if {path.name for path in root.iterdir()} != expected_entries:
            raise ReleaseError("release qualification step set is incomplete or contains residue")
        state_raw, _mode = _read_regular(
            self.layout.qualification_state_path(release_id),
            uid=self.layout.root_uid,
            gid=self.layout.root_gid,
            mode=0o444,
            maximum=65_536,
        )
        try:
            state = json.loads(state_raw)
        except (UnicodeDecodeError, ValueError) as exc:
            raise ReleaseError(f"cannot parse release qualification state: {exc}") from exc
        fields = {
            "schema_version", "release_id", "host_id", "boot_id",
            "canary_nonce", "contract_sha256", "grok_release_id", "model_id",
            "step_sha256s", "entrypoint_sha256", "broker_gate_sha256",
            "qualified_unix_ns", "overall_pass",
        }
        if not isinstance(state, dict) or set(state) != fields:
            raise ReleaseError("release qualification state has an unexpected shape")
        canary = {
            "release_id": release_id,
            "canary_nonce": state.get("canary_nonce"),
            "canary_kind": "release",
            "rung": "direct",
            "route_profile": "direct",
            "contract_sha256": None,
            "grok_release_id": state.get("grok_release_id"),
            "model_id": state.get("model_id"),
        }
        results: dict[str, dict[str, object]] = {}
        digests: dict[str, str] = {}
        for step in QUALIFICATION_STEPS:
            results[step], digests[step] = self._read_qualification_result(
                self.layout.qualification_result_path(release_id, step),
                step=step,
                canary=canary,
            )
        gate_digests = self._selected_gate_digests(release_id)
        if (
            state_raw != _canonical_json(state) + b"\n"
            or state.get("schema_version") != RELEASE_QUALIFICATION_SCHEMA_VERSION
            or state.get("release_id") != release_id
            or state.get("host_id") != self._host_id()
            or type(state.get("boot_id")) is not str
            or re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                str(state.get("boot_id")),
            ) is None
            or type(state.get("canary_nonce")) is not str
            or RELEASE_ID_RE.fullmatch(str(state.get("canary_nonce"))) is None
            or type(state.get("contract_sha256")) is not str
            or RELEASE_ID_RE.fullmatch(str(state.get("contract_sha256"))) is None
            or state.get("contract_sha256") != results["load32"].get("contract_sha256")
            or state.get("contract_sha256") != results["fault-recovery"].get("contract_sha256")
            or state.get("grok_release_id") != self._qualification_fake_identity(release_id)
            or state.get("model_id") != QUALIFICATION_FAKE_MODEL
            or state.get("step_sha256s") != digests
            or state.get("entrypoint_sha256") != gate_digests["entrypoint_sha256"]
            or state.get("broker_gate_sha256") != gate_digests["broker_gate_sha256"]
            or type(state.get("qualified_unix_ns")) is not int
            or state.get("qualified_unix_ns", 0) <= 0
            or state.get("overall_pass") is not True
        ):
            raise ReleaseError("release qualification state is failed or mismatched")
        return state, _sha256_bytes(state_raw)

    def _write_release_qualification(
        self,
        canary: Mapping[str, object],
    ) -> tuple[dict[str, object], str]:
        release_id = str(canary["release_id"])
        results: dict[str, dict[str, object]] = {}
        digests: dict[str, str] = {}
        for step in QUALIFICATION_STEPS:
            results[step], digests[step] = self._read_qualification_result(
                self.layout.qualification_result_path(release_id, step),
                step=step,
                canary=canary,
            )
        contract = results["load32"].get("contract_sha256")
        if contract != results["fault-recovery"].get("contract_sha256"):
            raise ReleaseError("release qualification steps used different contracts")
        gate_digests = self._selected_gate_digests(release_id)
        state = {
            "schema_version": RELEASE_QUALIFICATION_SCHEMA_VERSION,
            "release_id": release_id,
            "host_id": self._host_id(),
            "boot_id": self._boot_id(),
            "canary_nonce": canary["canary_nonce"],
            "contract_sha256": contract,
            "grok_release_id": canary["grok_release_id"],
            "model_id": canary["model_id"],
            "step_sha256s": digests,
            **gate_digests,
            "qualified_unix_ns": time.time_ns(),
            "overall_pass": True,
        }
        if _present(self.layout.qualification_state_path(release_id)):
            raise ReleaseError("release qualification state already exists")
        _atomic_write(
            self.layout.qualification_state_path(release_id),
            _canonical_json(state) + b"\n",
            mode=0o444,
            uid=self.layout.root_uid,
            gid=self.layout.root_gid,
            parent_mode=0o755,
        )
        return self._validate_release_qualification(release_id)

    def _run_qualification_verifier(
        self,
        *,
        release_id: str,
        step: str,
        auth_fd: int,
        environment: Mapping[str, str],
    ) -> SmokeResult:
        release_dir = self.layout.user_releases / release_id
        command = [
            "/usr/bin/python3", "-E", "-s", "-m",
            "grok_ms.qualification_verifier", "--mode", step,
        ]
        started = time.monotonic()
        session_deadline_monotonic_ns = (
            time.monotonic_ns()
            + RUNG_CANARY_TIMEOUT_SECONDS * 1_000_000_000
        )
        output_deadline_monotonic_ns = (
            session_deadline_monotonic_ns
            - QUALIFICATION_CONTAINMENT_RESERVE_SECONDS * 1_000_000_000
        )
        cleanup_deadline_monotonic_ns = (
            output_deadline_monotonic_ns
            - QUALIFICATION_TERMINAL_RESERVE_SECONDS * 1_000_000_000
        )
        work_deadline_monotonic_ns = (
            cleanup_deadline_monotonic_ns
            - QUALIFICATION_CLEANUP_RESERVE_SECONDS * 1_000_000_000
        )
        verifier_environment = dict(environment)
        verifier_environment[
            "GROK_QUALIFICATION_DEADLINE_MONOTONIC_NS"
        ] = str(work_deadline_monotonic_ns)
        verifier_environment[
            "GROK_QUALIFICATION_CLEANUP_DEADLINE_MONOTONIC_NS"
        ] = str(cleanup_deadline_monotonic_ns)
        process: subprocess.Popen[bytes] | None = None
        runner_scope: _RunnerCgroup | None = None
        leader_pidfd = -1
        session_reaped = False
        selector = selectors.DefaultSelector()
        stdout = bytearray()
        stderr = bytearray()
        failure: str | None = None
        try:
            demote = self._drop_identity(
                self.layout.target_uid,
                self.layout.target_gid,
            )
            inherited = (auth_fd,)
            if step in QUALIFICATION_STEPS and self._runner_scopes_required():
                runner_scope = self._create_runner_scope(
                    self.layout.target_uid,
                    self.layout.target_gid,
                    session_deadline_monotonic_ns,
                    runner_kind="qualification",
                    release_id=release_id,
                )
                verifier_environment.update(
                    {
                        "GROK_QUALIFICATION_RESOURCE_CGROUP_PATH": str(
                            runner_scope.record["scope_path"]
                        ),
                        "GROK_QUALIFICATION_RESOURCE_CGROUP_DEVICE": str(
                            runner_scope.record["scope_device"]
                        ),
                        "GROK_QUALIFICATION_RESOURCE_CGROUP_INODE": str(
                            runner_scope.record["scope_inode"]
                        ),
                    }
                )
                inherited = (auth_fd, runner_scope.descriptor)
            process = subprocess.Popen(
                command,
                cwd=release_dir,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
                pass_fds=inherited,
                start_new_session=True,
                env=verifier_environment,
                preexec_fn=(
                    runner_scope.preexec(demote)
                    if runner_scope is not None
                    else self._parent_death_preexec(demote)
                ),
            )
            if runner_scope is not None:
                runner_scope.mark_running()
            leader_pidfd = os.pidfd_open(process.pid, 0)
            os.set_inheritable(leader_pidfd, False)
            assert process.stdout is not None and process.stderr is not None
            streams = {
                process.stdout.fileno(): stdout,
                process.stderr.fileno(): stderr,
            }
            for descriptor in streams:
                os.set_blocking(descriptor, False)
                selector.register(descriptor, selectors.EVENT_READ)
            while streams:
                remaining = (
                    output_deadline_monotonic_ns - time.monotonic_ns()
                ) / 1_000_000_000
                if remaining <= 0:
                    failure = "timeout"
                    break
                for key, _mask in selector.select(min(remaining, 0.1)):
                    descriptor = int(key.fd)
                    try:
                        chunk = os.read(descriptor, 8192)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(descriptor)
                        streams.pop(descriptor, None)
                        continue
                    streams[descriptor].extend(chunk)
                    if len(stdout) + len(stderr) > 1024 * 1024:
                        failure = "output-limit"
                        break
                if failure is not None:
                    break
            if runner_scope is not None:
                runner_scope.cleanup(
                    session_deadline_monotonic_ns,
                    after_kill=self._runner_after_kill(
                        runner_scope,
                        runner_scope.record,
                        session_deadline_monotonic_ns,
                    ),
                )
                returncode = _reap_after_cgroup_cleanup(
                    process,
                    leader_pidfd,
                    deadline_monotonic_ns=session_deadline_monotonic_ns,
                )
                runner_scope.finalize_record()
                if returncode == 0 and runner_scope.runtime_recovery_applied:
                    # A verifier cannot claim cleanup_proved=true when the
                    # enclosing terminal sweep still had to reconcile durable
                    # runtime state.  Force the canonical result/exit check to
                    # reject that inconsistent pass.
                    returncode = 126
                    stderr.extend(
                        b"installer terminal recovery contradicted a passing qualification\n"
                    )
            else:
                returncode = _kill_session_group_before_reap(
                    process,
                    leader_pidfd,
                    graceful_seconds=0.0 if failure is not None else 5.0,
                    deadline_monotonic_ns=session_deadline_monotonic_ns,
                )
            session_reaped = True
            if failure is not None:
                returncode = 124 if failure == "timeout" else 125
            return SmokeResult(
                returncode,
                bytes(stdout[: 1024 * 1024]),
                bytes(stderr[: 1024 * 1024]),
                min(900_000, max(0, int((time.monotonic() - started) * 1000))),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ReleaseError(f"cannot execute fixed qualification verifier: {exc}") from exc
        finally:
            selector.close()
            containment_error: BaseException | None = None
            if runner_scope is not None:
                try:
                    runner_scope.cleanup(
                        session_deadline_monotonic_ns,
                        after_kill=self._runner_after_kill(
                            runner_scope,
                            runner_scope.record,
                            session_deadline_monotonic_ns,
                        ),
                    )
                except BaseException as exc:
                    containment_error = exc
                finally:
                    runner_scope.close()
            if (
                process is not None
                and not session_reaped
                and _session_is_quarantined(process)
            ):
                session_reaped = True
            if (
                process is not None
                and not session_reaped
                and process.returncode is not None
            ):
                session_reaped = True
            if process is not None and not session_reaped:
                try:
                    if runner_scope is not None and runner_scope.scope_removed:
                        _reap_after_cgroup_cleanup(
                            process,
                            leader_pidfd,
                            deadline_monotonic_ns=session_deadline_monotonic_ns,
                        )
                    elif leader_pidfd >= 0:
                        _kill_session_group_before_reap(
                            process,
                            leader_pidfd,
                            graceful_seconds=0.0,
                            deadline_monotonic_ns=session_deadline_monotonic_ns,
                        )
                    else:
                        _kill_session_group_without_pidfd_before_reap(
                            process,
                            deadline_monotonic_ns=session_deadline_monotonic_ns,
                        )
                    session_reaped = True
                except BaseException as exc:
                    containment_error = containment_error or exc
            if (
                runner_scope is not None
                and runner_scope.scope_removed
                and (process is None or session_reaped)
                and not runner_scope.cleaned
            ):
                try:
                    runner_scope.finalize_record()
                except BaseException as exc:
                    containment_error = containment_error or exc
            if process is not None:
                for stream in (process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()
            if leader_pidfd >= 0:
                os.close(leader_pidfd)
            if containment_error is not None:
                raise containment_error

    def qualification_exec(
        self,
        step: str,
        *,
        fault_at: str | None = None,
    ) -> QualificationExecResult:
        if step not in QUALIFICATION_MODES:
            raise ReleaseError("qualification step is not fixed")
        if fault_at not in {None, AFTER_CANARY_UNLINK, AFTER_DENY_CLEAR}:
            raise ReleaseError("unknown qualification fault stage")
        auth_fd = -1
        pending_fd = -1
        pending_path: Path | None = None
        try:
            with self._locked():
                if _present(self.layout.canary_terminal):
                    terminal = self._read_canary_terminal()
                    if (
                        step != "fault-recovery"
                        or terminal.get("disposition") != "release-qualified"
                    ):
                        raise ReleaseError(
                            "a different canary terminal operation requires recovery"
                        )
                    terminal_canary = terminal["canary"]
                    assert isinstance(terminal_canary, dict)
                    terminal_release = str(terminal["release_id"])
                    self._converge_canary_terminal(fault_at=fault_at)
                    existing, existing_digest = self._read_qualification_result(
                        self.layout.qualification_result_path(
                            terminal_release, "fault-recovery"
                        ),
                        step="fault-recovery",
                        canary=terminal_canary,
                    )
                    return QualificationExecResult(
                        terminal_release,
                        "fault-recovery",
                        str(existing["status"]),
                        0,
                        existing_digest,
                        None,
                        None,
                    )
                deny = self._deny_record()
                canary = self._read_rung_canary()
                release_id = str(canary["release_id"])
                if (
                    deny is None
                    or deny.get("operation") != "canary"
                    or deny.get("from_release") != release_id
                    or deny.get("to_release") != release_id
                    or not self._selection_is_exact(release_id, permit_deny=True)
                ):
                    raise ReleaseError("qualification lacks the exact fenced canary")
                self._validate_boot_inventory(release_id)
                kind = canary.get("canary_kind")
                if (kind == "release") != (step in QUALIFICATION_STEPS):
                    raise ReleaseError("qualification step does not match canary kind")
                if kind == "rung" and step != "real-pair":
                    raise ReleaseError("actual rung canary requires real-pair")
                if step == "real-pair":
                    self._validate_release_qualification(release_id)
                    root = self.layout.rung_transcript_dir(
                        release_id, str(canary["canary_nonce"])
                    )
                    result_path = self.layout.rung_qualification_path(
                        release_id, str(canary["canary_nonce"])
                    )
                else:
                    root = self.layout.qualification_release_dir(release_id)
                    result_path = self.layout.qualification_result_path(release_id, step)
                    _ensure_dir(root, 0o755, self.layout.root_uid, self.layout.root_gid)
                    if step == "load32" and _present(
                        self.layout.qualification_result_path(release_id, "fault-recovery")
                    ):
                        raise ReleaseError("release qualification step order is invalid")
                    if step == "fault-recovery":
                        self._read_qualification_result(
                            self.layout.qualification_result_path(release_id, "load32"),
                            step="load32",
                            canary=canary,
                        )
                if _present(result_path):
                    raise ReleaseError("qualification step result already exists (replay)")
                pending_path = root / f"pending-qualification-{step}.json"
                if _present(pending_path):
                    if self._pending_record_is_active(pending_path, recovery=True):
                        raise ReleaseError("qualification step is already active")
                    raise ReleaseError("qualification step has a crash-pending execution")
                auth_fd = os.open(
                    self.layout.canary_auth,
                    os.O_RDONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                )
                pending = {
                    "schema_version": QUALIFICATION_RESULT_SCHEMA_VERSION,
                    "release_id": release_id,
                    "host_id": self._host_id(),
                    "canary_nonce": canary["canary_nonce"],
                    "canary_kind": kind,
                    "step": step,
                    "started_unix_ns": time.time_ns(),
                }
                pending_fd = self._create_pending_record(pending_path, pending)
                environment = self._canary_environment(auth_fd, canary)

            result = self._run_qualification_verifier(
                release_id=release_id,
                step=step,
                auth_fd=auth_fd,
                environment=environment,
            )
            try:
                value = json.loads(result.stdout)
            except (UnicodeDecodeError, ValueError) as exc:
                raise ReleaseError("qualification verifier returned invalid JSON") from exc
            if result.stdout != _canonical_json(value) + b"\n":
                raise ReleaseError("qualification verifier output is not one canonical line")
            value = self._validate_qualification_result_value(
                value, step=step, canary=canary, require_pass=False
            )
            expected_rc = {"passed": 0, "failed": 2, "blocked": 3}[str(value["status"])]
            if result.returncode != expected_rc:
                raise ReleaseError("qualification verifier status/exit code disagree")
            result_digest = _sha256_bytes(result.stdout)

            with self._locked():
                if self._read_rung_canary() != canary:
                    raise ReleaseError("qualification canary changed during execution")
                current_deny = self._deny_record()
                if (
                    current_deny is None
                    or current_deny.get("operation") != "canary"
                    or current_deny.get("from_release") != release_id
                    or current_deny.get("to_release") != release_id
                    or not self._selection_is_exact(release_id, permit_deny=True)
                ):
                    raise ReleaseError(
                        "qualification fence changed during execution"
                    )
                if pending_path is None or not _present(pending_path):
                    raise ReleaseError("qualification pending intent disappeared")
                if value["status"] == "passed":
                    _exclusive_write(
                        result_path,
                        result.stdout,
                        mode=0o444,
                        uid=self.layout.root_uid,
                        gid=self.layout.root_gid,
                        parent_mode=0o755,
                    )
                pending_path.unlink()
                _fsync_dir(pending_path.parent)
                if value["status"] == "passed" and step == "fault-recovery":
                    self._write_release_qualification(canary)
                    self._finish_canary_terminal(
                        canary,
                        "release-qualified",
                        fault_at=fault_at,
                    )
            return QualificationExecResult(
                release_id,
                step,
                str(value["status"]),
                result.returncode,
                result_digest,
                str(value["error_code"]) if value["error_code"] is not None else None,
                str(value["error_sha256"])
                if value["error_sha256"] is not None
                else None,
            )
        finally:
            if auth_fd >= 0:
                os.close(auth_fd)
            if pending_fd >= 0:
                fcntl.flock(pending_fd, fcntl.LOCK_UN)
                os.close(pending_fd)

    def canary_exec(self, argv: tuple[str, ...]) -> CanaryExecResult:
        if (
            len(argv) > 128
            or any(
                type(item) is not str
                or "\x00" in item
                or len(item.encode("utf-8")) > 4096
                for item in argv
            )
            or sum(len(item.encode("utf-8")) for item in argv) > 65_536
        ):
            raise ReleaseError("rung canary argv exceeds its closed bound")
        auth_fd = -1
        pending_record_fd = -1
        pending_path: Path | None = None
        process: subprocess.Popen[bytes] | None = None
        leader_pidfd = -1
        session_reaped = False
        containment_deadline_monotonic_ns = 0
        try:
            # Serialize only authorization and durable intent publication.  The
            # child lifetime must remain concurrent so a canary can prove the
            # multi-session behavior it is intended to qualify.
            with self._locked():
                deny = self._deny_record()
                record = self._read_rung_canary()
                if record.get("canary_kind") != "rung":
                    raise ReleaseError(
                        "free-form canary execution is manual and unavailable during release qualification"
                    )
                release_id = str(record["release_id"])
                if (
                    deny is None
                    or deny.get("operation") != "canary"
                    or deny.get("from_release") != release_id
                    or deny.get("to_release") != release_id
                    or not self._selection_is_exact(release_id, permit_deny=True)
                ):
                    raise ReleaseError("rung canary is not the exact active fenced release")
                self._validate_boot_inventory(release_id)
                nonce = str(record["canary_nonce"])
                run_root = self.layout.rung_transcript_dir(release_id, nonce)
                active_pending = self._pending_rung_executions(
                    release_id=release_id,
                    nonce=nonce,
                    rung=str(record["rung"]),
                    contract_sha256=str(record["contract_sha256"]),
                    grok_release_id=str(record["grok_release_id"]),
                )
                if any(
                    not self._pending_record_is_active(candidate_path)
                    for _value, candidate_path in active_pending
                ):
                    raise ReleaseError("rung canary has a crash-pending execution")
                transcripts = self._rung_transcript_digests(
                    release_id=release_id,
                    nonce=nonce,
                    rung=str(record["rung"]),
                    contract_sha256=str(record["contract_sha256"]),
                    grok_release_id=str(record["grok_release_id"]),
                    require_success=False,
                    allow_pending=True,
                )
                if len(transcripts) + len(active_pending) >= 64:
                    raise ReleaseError("rung canary execution transcript set is full")

                auth_fd = os.open(
                    self.layout.canary_auth,
                    os.O_RDONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                )
                environment = self._canary_environment(auth_fd, record)
                run_id = uuid.uuid4().hex
                started_unix_ns = time.time_ns()
                argv_sha256 = _sha256_bytes(_canonical_json(list(argv)) + b"\n")
                environment_sha256 = _sha256_bytes(
                    _canonical_json(dict(sorted(environment.items()))) + b"\n"
                )
                pending = {
                    "schema_version": RUNG_TRANSCRIPT_SCHEMA_VERSION,
                    "transcript_kind": "manual",
                    "release_id": release_id,
                    "host_id": self._host_id(),
                    "rung": str(record["rung"]),
                    "contract_sha256": str(record["contract_sha256"]),
                    "grok_release_id": str(record["grok_release_id"]),
                    "canary_nonce": nonce,
                    "run_id": run_id,
                    "argv_sha256": argv_sha256,
                    "started_unix_ns": started_unix_ns,
                }
                pending_path = run_root / f"pending-{run_id}.json"
                pending_record_fd = self._create_pending_record(pending_path, pending)

            started_monotonic_ns = time.monotonic_ns()
            containment_deadline_monotonic_ns = (
                started_monotonic_ns
                + (
                    RUNG_CANARY_TIMEOUT_SECONDS
                    + GATE_SMOKE_CONTAINMENT_SECONDS
                )
                * 1_000_000_000
            )
            try:
                demote = self._drop_identity(
                    self.layout.target_uid,
                    self.layout.target_gid,
                )
                inherited = (auth_fd,)
                process = subprocess.Popen(
                    [str(self.layout.entrypoint), *argv],
                    pass_fds=inherited,
                    close_fds=True,
                    start_new_session=True,
                    env=environment,
                    preexec_fn=self._parent_death_preexec(demote),
                )
                leader_pidfd = os.pidfd_open(process.pid, 0)
                os.set_inheritable(leader_pidfd, False)
                completed = _pidfd_exit_ready(
                    leader_pidfd,
                    RUNG_CANARY_TIMEOUT_SECONDS,
                )
                returncode = _kill_session_group_before_reap(
                    process,
                    leader_pidfd,
                    graceful_seconds=0.0,
                    deadline_monotonic_ns=(
                        containment_deadline_monotonic_ns
                    ),
                )
                session_reaped = True
                if not completed:
                    returncode = 124
            except (OSError, subprocess.SubprocessError) as exc:
                raise ReleaseError(f"cannot execute authorized rung canary: {exc}") from exc

            completed_unix_ns = time.time_ns()
            duration_ms = max(
                0, (time.monotonic_ns() - started_monotonic_ns) // 1_000_000
            )
            transcript = {
                **pending,
                "environment_sha256": environment_sha256,
                "completed_unix_ns": completed_unix_ns,
                "duration_ms": duration_ms,
                "returncode": returncode,
                "passed": returncode == 0,
            }
            transcript_raw = _canonical_json(transcript) + b"\n"
            transcript_sha256 = _sha256_bytes(transcript_raw)

            # Finalization is serialized again.  The per-run lock closes the
            # race with abort while the child has exited but its transcript is
            # not yet durable.
            with self._locked():
                current = self._read_rung_canary()
                deny = self._deny_record()
                if (
                    current != record
                    or deny is None
                    or deny.get("operation") != "canary"
                    or deny.get("from_release") != release_id
                    or deny.get("to_release") != release_id
                    or not self._selection_is_exact(release_id, permit_deny=True)
                ):
                    raise ReleaseError("rung canary authorization changed during execution")
                pending_records = self._pending_rung_executions(
                    release_id=release_id,
                    nonce=nonce,
                    rung=str(record["rung"]),
                    contract_sha256=str(record["contract_sha256"]),
                    grok_release_id=str(record["grok_release_id"]),
                )
                matching = [
                    item
                    for item in pending_records
                    if item[0].get("run_id") == run_id
                ]
                if (
                    len(matching) != 1
                    or matching[0][0] != pending
                    or matching[0][1] != pending_path
                ):
                    raise ReleaseError("rung canary pending execution changed identity")
                _exclusive_write(
                    run_root / f"{transcript_sha256}.json",
                    transcript_raw,
                    mode=0o444,
                    uid=self.layout.root_uid,
                    gid=self.layout.root_gid,
                    parent_mode=0o755,
                )
                pending_path.unlink()
                _fsync_dir(run_root)
            return CanaryExecResult(
                release_id,
                str(record["rung"]),
                returncode,
                run_id,
                transcript_sha256,
            )
        finally:
            containment_error: BaseException | None = None
            if process is not None and not session_reaped:
                try:
                    if leader_pidfd >= 0:
                        _kill_session_group_before_reap(
                            process,
                            leader_pidfd,
                            graceful_seconds=0.0,
                            deadline_monotonic_ns=(
                                containment_deadline_monotonic_ns
                            ),
                        )
                    else:
                        _kill_session_group_without_pidfd_before_reap(
                            process,
                            deadline_monotonic_ns=(
                                containment_deadline_monotonic_ns
                            ),
                        )
                    session_reaped = True
                except BaseException as exc:
                    containment_error = containment_error or exc
            if leader_pidfd >= 0:
                os.close(leader_pidfd)
            if auth_fd >= 0:
                os.close(auth_fd)
            if pending_record_fd >= 0:
                fcntl.flock(pending_record_fd, fcntl.LOCK_UN)
                os.close(pending_record_fd)
            if containment_error is not None:
                raise containment_error

    def _derive_rung_evidence(
        self,
        canary: Mapping[str, object],
    ) -> tuple[dict[str, object], dict[str, str]]:
        release_id = str(canary["release_id"])
        release_state, release_digest = self._validate_release_qualification(release_id)
        real_result, real_digest = self._read_qualification_result(
            self.layout.rung_qualification_path(
                release_id, str(canary["canary_nonce"])
            ),
            step="real-pair",
            canary=canary,
        )
        release_canary = {
            "release_id": release_id,
            "canary_nonce": release_state["canary_nonce"],
            "canary_kind": "release",
            "rung": "direct",
            "route_profile": "direct",
            "contract_sha256": None,
            "grok_release_id": release_state["grok_release_id"],
            "model_id": release_state["model_id"],
        }
        release_results = [
            self._read_qualification_result(
                self.layout.qualification_result_path(release_id, step),
                step=step,
                canary=release_canary,
            )[0]
            for step in QUALIFICATION_STEPS
        ]
        combined = _sha256_bytes(
            _canonical_json(
                {
                    "release_qualification_sha256": release_digest,
                    "real_pair_result_sha256": real_digest,
                }
            )
            + b"\n"
        )
        value = {
            "schema_version": RUNG_EVIDENCE_SCHEMA_VERSION,
            "release_id": release_id,
            "host_id": self._host_id(),
            "rung": canary["rung"],
            "route_profile": canary["route_profile"],
            "contract_sha256": canary["contract_sha256"],
            "grok_release_id": canary["grok_release_id"],
            "model_id": canary["model_id"],
            "measured_unix_ns": time.time_ns(),
            "canary_nonce": canary["canary_nonce"],
            "release_qualification_sha256": release_digest,
            "real_pair_result_sha256": real_digest,
            "measurements": {
                "duration_ms": max(
                    1,
                    sum(int(item["duration_ms"]) for item in release_results)
                    + int(real_result["duration_ms"]),
                ),
                "fault_load_canary_verified": True,
                "host_limits_verified": True,
                "result_sha256": combined,
                "post_repair_reconnect_cache_execution_units_verified": True,
                "shared_route": True,
                "teardown_clean": True,
                "transport_timing_verified": True,
                "two_sessions": True,
            },
            "overall_pass": True,
        }
        digest = _sha256_bytes(_canonical_json(value) + b"\n")
        return value, self._validate_rung_evidence_value(
            release_id, value, expected_digest=digest
        )

    def promote_rung(
        self,
        evidence_file: Path | None = None,
        *,
        fault_at: str | None = None,
    ) -> InstallResult:
        if evidence_file is not None:
            raise ReleaseError(
                "external rung evidence is not accepted; promotion is installer-derived"
            )
        with self._locked():
            if _present(self.layout.canary_terminal):
                terminal = self._read_canary_terminal()
                if terminal.get("disposition") != "rung-promoted":
                    raise ReleaseError(
                        "a different canary terminal operation requires recovery"
                    )
                converged = self._converge_canary_terminal(fault_at=fault_at)
                return InstallResult(
                    converged.release_id,
                    converged.changed,
                    "promote-rung",
                )
            deny = self._deny_record()
            canary = self._read_rung_canary()
            release_id = str(canary["release_id"])
            if (
                deny is None
                or deny.get("operation") != "canary"
                or deny.get("from_release") != release_id
                or deny.get("to_release") != release_id
                or not self._selection_is_exact(release_id, permit_deny=True)
            ):
                raise ReleaseError("rung promotion lacks an exact fenced canary")
            if canary.get("canary_kind") != "rung":
                raise ReleaseError("release qualification canary cannot promote a rung")
            value, record = self._derive_rung_evidence(canary)
            raw = _canonical_json(value) + b"\n"
            digest = _sha256_bytes(raw)
            for field in ("rung", "contract_sha256", "grok_release_id"):
                if record[field] != canary[field]:
                    raise ReleaseError(f"derived rung evidence mismatches canary {field}")
            if value.get("canary_nonce") != canary.get("canary_nonce"):
                raise ReleaseError("attested rung evidence mismatches canary nonce")
            destination = self.layout.rung_evidence_path(release_id, digest)
            _ensure_dir(
                destination.parent,
                0o755,
                self.layout.root_uid,
                self.layout.root_gid,
            )
            _atomic_write(
                destination,
                raw,
                mode=0o444,
                uid=self.layout.root_uid,
                gid=self.layout.root_gid,
                parent_mode=0o755,
            )
            selected = self._read_json(
                self.layout.selected,
                uid=self.layout.target_uid,
                gid=self.layout.target_gid,
                mode=0o444,
            )
            existing = selected.get("qualified_rungs")
            if not isinstance(existing, list):
                raise ReleaseError("selected qualified rung set is invalid")
            qualified = [
                item
                for item in self._validate_qualified_rungs(release_id, existing)
                if not (
                    item["rung"] == record["rung"]
                    and item["contract_sha256"] == record["contract_sha256"]
                    and item["grok_release_id"] == record["grok_release_id"]
                )
            ]
            qualified.append(record)
            operation = selected.get("operation")
            if operation not in {"install", "rollback"}:
                raise ReleaseError("selected release operation is invalid")
            evidence_digest = self._validate_evidence(release_id, str(operation))
            self._remove_qualification_fault_marker(canary)
            self._assert_switch_quiescent()
            with self._selection_locked(self.switch_timeout):
                self._assert_switch_quiescent(broker_inventory=False)
                self._validate_boot_inventory(release_id)
                self._publish_selection(
                    release_id,
                    str(operation),
                    evidence_sha256=evidence_digest,
                    selection_phase="READY",
                    fault_at=None,
                    selector_faults=False,
                    qualified_rungs=qualified,
                )
                if not self._selection_is_exact(release_id, permit_deny=True):
                    raise ReleaseError("rung-qualified selection is not coherent")
                # Publish the durable terminal decision while selection is
                # still exclusive, but do not converge it under this lock.
                # Convergence performs deny-safe broker inventory, whose
                # selected broker must acquire a shared selection lock.  Doing
                # that while this process holds LOCK_EX self-deadlocks.
                self._prepare_canary_terminal(canary, "rung-promoted")
            self._converge_canary_terminal(fault_at=fault_at)
            return InstallResult(release_id, True, "promote-rung")

    def revalidate_boot(self) -> InstallResult:
        with self._locked():
            if _present(self.layout.canary_terminal):
                self._converge_canary_terminal()
            if _present(self.layout.rollback_deny):
                raise ReleaseError("cannot revalidate boot inventory while deny is active")
            release_id = self.active_release_id()
            if release_id is None or not self._selection_is_exact(release_id):
                raise ReleaseError("boot revalidation requires an exact READY selection")
            snapshot = self._assert_switch_quiescent()
            with self._selection_locked(self.switch_timeout):
                if not self._selection_is_exact(release_id):
                    raise ReleaseError(
                        "boot revalidation selection changed before publication"
                    )
                locked_snapshot = self._assert_switch_quiescent(
                    broker_inventory=False
                )
                locked_snapshot["broker"] = snapshot["broker"]
                self._write_boot_inventory(release_id, locked_snapshot)
            self._validate_boot_inventory(release_id)
            return InstallResult(release_id, True, "revalidate")

    def resume(self) -> InstallResult:
        with self._locked():
            if _present(self.layout.canary_terminal):
                terminal = self._read_canary_terminal()
                converged = self._converge_canary_terminal()
                return InstallResult(
                    converged.release_id,
                    converged.changed,
                    str(terminal["disposition"]),
                )
            deny = self._deny_record()
            if deny is None:
                raise ReleaseError("no interrupted release operation is fenced")
            operation = deny.get("operation")
            if operation == "canary":
                raise ReleaseError("rung canary must be promoted or aborted")
            if operation not in {"install", "rollback"}:
                raise ReleaseError("deny ledger operation is invalid")
            target = str(deny.get("to_release", ""))
            source = deny.get("from_release")
            if RELEASE_ID_RE.fullmatch(target) is None:
                raise ReleaseError("deny ledger target release is invalid")
            if source is not None and (
                type(source) is not str or RELEASE_ID_RE.fullmatch(source) is None
            ):
                raise ReleaseError("deny ledger source release is invalid")
            self.validate_target_release_pair(target)
            self._converge_deny_release_access(deny)
            self._drain_active(
                allow_root_artifact_residue=(
                    operation == "install" and source != target
                )
            )
            self._promote_or_restore(target, str(operation), None, source)
            return InstallResult(target, True, "resume")

    def abort_restore(
        self,
        restore_from: str | None = None,
        *,
        fault_at: str | None = None,
    ) -> InstallResult:
        if fault_at not in {None, AFTER_CANARY_UNLINK, AFTER_DENY_CLEAR}:
            raise ReleaseError("unknown abort fault stage")
        with self._locked():
            if _present(self.layout.canary_terminal):
                terminal = self._read_canary_terminal()
                release_id = str(terminal["release_id"])
                if restore_from is not None and restore_from != release_id:
                    raise ReleaseError("--restore-from differs from the terminal record")
                self._converge_canary_terminal(fault_at=fault_at)
                return InstallResult(release_id, True, "abort")
            deny = self._deny_record()
            if deny is None:
                raise ReleaseError("no interrupted release operation is fenced")
            operation = deny.get("operation")
            source = deny.get("from_release")
            target = deny.get("to_release")
            if operation == "canary":
                if source != target or type(source) is not str:
                    raise ReleaseError("canary deny ledger is invalid")
                if restore_from is not None and restore_from != source:
                    raise ReleaseError("--restore-from differs from the deny ledger")
                if not self._selection_is_exact(source, permit_deny=True):
                    raise ReleaseError("canary selection is not coherent enough to abort")
                canary = self._read_rung_canary()
                self._finish_canary_terminal(
                    canary,
                    "abort",
                    fault_at=fault_at,
                )
                return InstallResult(source, True, "abort")
            if operation not in {"install", "rollback"}:
                raise ReleaseError("deny ledger operation is invalid")
            if type(source) is not str or RELEASE_ID_RE.fullmatch(source) is None:
                raise ReleaseError("deny ledger has no restorable prior release")
            if restore_from is not None and restore_from != source:
                raise ReleaseError("--restore-from differs from the deny ledger")
            self.validate_target_release_pair(source)
            self._converge_deny_release_access(deny)
            self._drain_active()
            self._complete_promoted_selection(source, "rollback", None)
            return InstallResult(source, True, "abort")

    def install(self, *, fault_at: str | None = None) -> InstallResult:
        if fault_at is not None and fault_at not in INSTALL_FAULT_STAGES:
            raise ReleaseError(f"unknown install fault stage: {fault_at}")
        with self._locked():
            if _present(self.layout.canary_terminal):
                self._converge_canary_terminal()
            plan = self.plan_release()
            old_user = self.active_release_id()
            old_root = self.root_active_release_id()
            if not _present(self.layout.rollback_deny) and self._selection_is_exact(plan.release_id):
                inventory = self._broker_inventory(allow_active_runtime=True)
                if inventory.get("active") is not True:
                    suspects = self._legacy_openvpn_process_inventory()
                    if suspects:
                        raise ReleaseError(
                            "legacy OpenVPN process blocks idempotent install: "
                            f"count={len(suspects)}"
                        )
                return InstallResult(plan.release_id, False, "install")
            if old_user != old_root and (old_user is not None or old_root is not None):
                # A matching interrupted deny may legitimately explain this below;
                # without it, never invent which side was authoritative.
                if not _present(self.layout.rollback_deny):
                    raise ReleaseError("unfenced mixed root/user selectors")
            existing_deny = self._deny_record()
            deny_source = (
                existing_deny.get("from_release")
                if existing_deny is not None
                else old_user
            )
            if deny_source is not None and type(deny_source) is not str:
                raise ReleaseError("install deny has an invalid rollback release")
            # Repeating the same legacy command remains compatible, but the
            # authoritative source is always the durable ledger.  `resume`
            # is the source-independent recovery interface.
            self._publish_deny("install", deny_source, plan.release_id)
            deny_record = self._deny_record()
            assert deny_record is not None
            from_release = deny_record.get("from_release")
            if from_release is not None and type(from_release) is not str:
                raise ReleaseError("install deny has an invalid rollback release")
            self._converge_deny_release_access(deny_record)
            self._fault(fault_at, AFTER_DENY)
            if (
                from_release == plan.release_id
                and old_user == plan.release_id
                and old_root == plan.release_id
                and self._selection_is_exact(
                    plan.release_id, permit_deny=True
                )
            ):
                self._clear_deny()
                inventory = self._broker_inventory(allow_active_runtime=True)
                if inventory.get("active") is not True:
                    suspects = self._legacy_openvpn_process_inventory()
                    if suspects:
                        raise ReleaseError(
                            "legacy OpenVPN process blocks idempotent install: "
                            f"count={len(suspects)}"
                        )
                return InstallResult(plan.release_id, False, "install")
            self._drain_active(
                allow_root_artifact_residue=(
                    from_release != plan.release_id
                )
            )
            root_stage, root_final = self._stage_release(plan, "root")
            self._fault(fault_at, AFTER_ROOT_STAGE)
            self._publish_stage(root_stage, root_final)
            self._fault(fault_at, AFTER_ROOT_PUBLISH)

            user_stage, user_final = self._stage_release(plan, "user")
            self._fault(fault_at, AFTER_USER_STAGE)
            self._publish_stage(user_stage, user_final)
            self._fault(fault_at, AFTER_USER_PUBLISH)

            self._promote_or_restore(
                plan.release_id,
                "install",
                fault_at,
                from_release,
            )
            return InstallResult(plan.release_id, True, "install")

    def rollback(self, release_id: str, *, fault_at: str | None = None) -> InstallResult:
        if not RELEASE_ID_RE.fullmatch(release_id):
            raise ReleaseError(f"invalid rollback release ID: {release_id!r}")
        if fault_at is not None and fault_at not in ROLLBACK_FAULT_STAGES:
            raise ReleaseError(f"unknown rollback fault stage: {fault_at}")
        with self._locked():
            if _present(self.layout.canary_terminal):
                self._converge_canary_terminal()
            self.validate_target_release_pair(release_id)
            old_user = self.active_release_id()
            old_root = self.root_active_release_id()
            if not _present(self.layout.rollback_deny) and self._selection_is_exact(release_id):
                return InstallResult(release_id, False, "rollback")
            if old_user != old_root and not _present(self.layout.rollback_deny):
                raise ReleaseError("unfenced mixed root/user selectors")
            existing_deny = self._deny_record()
            deny_source = (
                existing_deny.get("from_release")
                if existing_deny is not None
                else old_user
            )
            if deny_source is not None and type(deny_source) is not str:
                raise ReleaseError("rollback deny has an invalid prior release")
            self._publish_deny("rollback", deny_source, release_id)
            deny_record = self._deny_record()
            assert deny_record is not None
            from_release = deny_record.get("from_release")
            if from_release is not None and type(from_release) is not str:
                raise ReleaseError("rollback deny has an invalid prior release")
            self._converge_deny_release_access(deny_record)
            self._fault(fault_at, AFTER_DENY)
            if (
                from_release == release_id
                and old_user == release_id
                and old_root == release_id
                and self._selection_is_exact(release_id, permit_deny=True)
            ):
                self._clear_deny()
                return InstallResult(release_id, False, "rollback")
            self._drain_active()
            self._promote_or_restore(
                release_id,
                "rollback",
                fault_at,
                from_release,
            )
            return InstallResult(release_id, True, "rollback")

    def preview_install(self) -> dict[str, object]:
        plan = self.plan_release()
        active_user = self._read_selector_for_status("user")
        active_root = self._read_selector_for_status("root")
        return {
            "schema_version": SCHEMA_VERSION,
            "operation": "install",
            "applied": False,
            "release_id": plan.release_id,
            "active_user_release_id": active_user,
            "active_root_release_id": active_root,
            "would_change": not self._selection_is_exact(plan.release_id),
            "rollback_denied": _present(self.layout.rollback_deny),
        }

    def preview_rollback(self, release_id: str) -> dict[str, object]:
        self.validate_target_release_pair(release_id)
        return {
            "schema_version": SCHEMA_VERSION,
            "operation": "rollback",
            "applied": False,
            "release_id": release_id,
            "active_user_release_id": self._read_selector_for_status("user"),
            "active_root_release_id": self._read_selector_for_status("root"),
            "would_change": not self._selection_is_exact(release_id),
            "rollback_denied": _present(self.layout.rollback_deny),
        }

    def _read_selector_for_status(self, kind: str) -> str | None:
        try:
            return self.active_release_id() if kind == "user" else self.root_active_release_id()
        except ReleaseError:
            return None

    def status(self) -> dict[str, object]:
        active_user = self._read_selector_for_status("user")
        active_root = self._read_selector_for_status("root")
        denied = _present(self.layout.rollback_deny)
        user_releases = self._release_names(self.layout.user_releases)
        user_release_modes: dict[str, str] = {}
        archived_user_releases: list[str] = []
        exposed_user_releases: list[str] = []
        rollback_eligible_releases: list[str] = []
        eligibility_complete = True
        may_read_archived = os.geteuid() == self.layout.root_uid
        for release_id in user_releases:
            path = self.layout.user_releases / release_id
            try:
                info = path.lstat()
            except OSError:
                user_release_modes[release_id] = "unreadable"
                eligibility_complete = False
                continue
            mode = stat.S_IMODE(info.st_mode)
            user_release_modes[release_id] = f"{mode:04o}"
            if mode == ARCHIVED_RELEASE_MODE:
                archived_user_releases.append(release_id)
            elif mode == ACTIVE_RELEASE_MODE:
                exposed_user_releases.append(release_id)
            if mode == ARCHIVED_RELEASE_MODE and not may_read_archived:
                eligibility_complete = False
                continue
            try:
                self.validate_target_release_pair(release_id)
            except ReleaseError:
                continue
            rollback_eligible_releases.append(release_id)
        release_access_policy_valid = bool(
            not denied
            and active_user
            and self._release_access_is_exact({active_user})
        )
        coherent = bool(
            not denied
            and active_user
            and active_user == active_root
            and self._selection_is_exact(active_user)
        )
        boot_valid = False
        qualified_rungs: list[dict[str, str]] = []
        if coherent and active_user is not None:
            try:
                self._validate_boot_inventory(active_user)
                boot_valid = True
                selected = self._read_json(
                    self.layout.selected,
                    uid=self.layout.target_uid,
                    gid=self.layout.target_gid,
                    mode=0o444,
                )
                records = selected.get("qualified_rungs")
                if isinstance(records, list):
                    qualified_rungs = self._validate_qualified_rungs(active_user, records)
            except ReleaseError:
                boot_valid = False
        return {
            "schema_version": SCHEMA_VERSION,
            "active_release_id": active_user if coherent else None,
            "active_user_release_id": active_user,
            "active_root_release_id": active_root,
            "active_release_valid": coherent,
            "boot_inventory_valid": boot_valid,
            "qualified_rungs": qualified_rungs,
            "rollback_denied": denied,
            "deny_valid": self._deny_valid(),
            "release_access_policy_valid": release_access_policy_valid,
            "rollback_eligibility_complete": eligibility_complete,
            "rollback_eligible_releases": rollback_eligible_releases,
            "archived_user_releases": archived_user_releases,
            "exposed_user_releases": exposed_user_releases,
            "user_release_modes": user_release_modes,
            "user_releases": user_releases,
            "root_releases": self._release_names(self.layout.root_releases),
        }

    def _deny_valid(self) -> bool:
        if not _present(self.layout.rollback_deny):
            return False
        try:
            record = self._deny_record()
            return bool(
                record
                and set(record)
                == {"schema_version", "operation", "from_release", "to_release"}
                and record.get("schema_version") == CONTROL_SCHEMA_VERSION
                and record.get("operation") in ("install", "rollback", "canary")
                and (
                    record.get("from_release") is None
                    or RELEASE_ID_RE.fullmatch(str(record.get("from_release"))) is not None
                )
                and RELEASE_ID_RE.fullmatch(str(record.get("to_release", "")))
            )
        except ReleaseError:
            return False

    @staticmethod
    def _release_names(root: Path) -> list[str]:
        if not root.is_dir() or root.is_symlink():
            return []
        return sorted(
            path.name
            for path in root.iterdir()
            if path.is_dir() and not path.is_symlink() and RELEASE_ID_RE.fullmatch(path.name)
        )


def _default_runtime_files(source: Path) -> tuple[str, ...]:
    source = Path(source)
    selected: list[str] = []
    for name in DECLARED_RUNTIME_REQUIRED:
        path = source / name
        if not path.is_file() or path.is_symlink():
            raise ReleaseError(f"missing declared runtime file: {name}")
        selected.append(name)
    brokers = [
        name
        for name in DECLARED_BROKER_CANDIDATES
        if (source / name).is_file() and not (source / name).is_symlink()
    ]
    if len(brokers) != 1:
        raise ReleaseError(f"exactly one declared VPN broker is required: {brokers}")
    selected.extend(brokers)

    package = source / DECLARED_PACKAGE_ROOT
    if not package.is_dir() or package.is_symlink():
        raise ReleaseError(f"missing safe runtime package: {DECLARED_PACKAGE_ROOT}")
    for path in sorted(package.rglob("*")):
        relative = path.relative_to(source)
        if any(
            part in EXCLUDED_PACKAGE_PARTS or part.startswith(".")
            for part in relative.parts
        ):
            continue
        if path.is_symlink():
            raise ReleaseError(f"runtime package contains a symlink: {relative}")
        if path.is_dir():
            continue
        if path.suffix == ".py":
            selected.append(relative.as_posix())
    if f"{DECLARED_PACKAGE_ROOT}/__init__.py" not in selected:
        raise ReleaseError("runtime package lacks __init__.py")
    if DIRECT_ADMISSION_RUNTIME not in selected:
        raise ReleaseError(
            "runtime package lacks mandatory direct self-admission module"
        )
    for relative, markers in DIRECT_ADMISSION_MARKERS.items():
        raw, _mode = _read_regular(source / relative)
        if any(marker not in raw for marker in markers):
            raise ReleaseError(
                "runtime source lacks the mandatory direct self-admission contract: "
                f"{relative}"
            )
    return tuple(sorted(selected))


def _default_root_files(runtime_files: Iterable[str]) -> dict[str, str]:
    names = set(runtime_files)

    def choose(role: str, candidates: Iterable[str]) -> str:
        matches = [name for name in candidates if name in names]
        if len(matches) != 1:
            raise ReleaseError(f"cannot uniquely discover root {role} helper: {matches}")
        return matches[0]

    return {
        "broker": choose("broker", DECLARED_BROKER_CANDIDATES),
        "vpngate": choose("vpngate", ("vpngate-connect.sh",)),
        "relay": choose("relay", ("socks-netns.py",)),
        "sanitizer": choose("sanitizer", ("sanitize.awk",)),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "command",
        choices=(
            "plan", "install", "rollback", "status", "resume", "abort",
            "revalidate", "begin-release-qualification", "begin-rung-canary",
            "canary-exec", "promote-rung",
        ),
    )
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--prefix", type=Path)
    parser.add_argument("--home", type=Path)
    parser.add_argument(
        "--test-openvpn-binary",
        type=Path,
        help="prefix-only safe OpenVPN prerequisite fixture",
    )
    parser.add_argument("--release-id", help="target release for rollback")
    parser.add_argument("--restore-from", help="must match the deny ledger source release")
    parser.add_argument("--rung", help="closed rung name for begin-rung-canary")
    parser.add_argument(
        "--route-profile",
        help=(
            "exact route profile: direct, iphone, vpn, home:<label>, "
            "auto, or auto-no-direct"
        ),
    )
    parser.add_argument("--contract-sha256", help="exact RouteContract digest")
    parser.add_argument("--grok-release-id", help="exact verified Grok executable identity")
    parser.add_argument("--model-id", help="exact concrete model for rung qualification")
    parser.add_argument(
        "--evidence-file",
        type=Path,
        help="legacy external evidence (rejected; promotion is installer-derived)",
    )
    parser.add_argument(
        "--canary-arg",
        action="append",
        default=[],
        help="one argument forwarded by canary-exec; repeat as needed",
    )
    parser.add_argument(
        "--qualification-step",
        choices=sorted(QUALIFICATION_MODES),
        help="installer-owned fixed qualification step for canary-exec",
    )
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--apply", action="store_true", help="perform install or rollback")
    action.add_argument("--dry-run", action="store_true", help="explicitly request a read-only preview")
    parser.add_argument(
        "--fault-at",
        choices=sorted({*INSTALL_FAULT_STAGES, AFTER_CANARY_UNLINK}),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command in ("plan", "status") and (args.apply or args.dry_run or args.fault_at):
        raise ReleaseError(f"{args.command} does not accept action or fault flags")
    if args.fault_at and not args.apply:
        raise ReleaseError("--fault-at requires --apply")
    if args.test_openvpn_binary is not None and args.prefix is None:
        raise ReleaseError("--test-openvpn-binary requires --prefix")
    layout = Layout.defaults(
        args.source,
        prefix=args.prefix,
        home=args.home,
        test_openvpn_binary=args.test_openvpn_binary,
    )
    runtime_files = _default_runtime_files(args.source)
    installer = ReleaseInstaller(
        layout,
        runtime_files=runtime_files,
        root_files=_default_root_files(runtime_files),
    )
    mutating = {
        "resume", "abort", "revalidate", "begin-release-qualification",
        "begin-rung-canary",
        "canary-exec", "promote-rung",
    }
    if args.command in mutating and not args.apply:
        raise ReleaseError(f"{args.command} requires --apply")
    if args.command in mutating and args.dry_run:
        raise ReleaseError(f"{args.command} does not support --dry-run")
    if args.command not in {
        "install", "rollback", "abort", "promote-rung", "canary-exec"
    } and args.fault_at:
        raise ReleaseError(f"{args.command} does not support --fault-at")
    if args.apply and args.prefix is None and os.geteuid() != layout.root_uid:
        raise ReleaseError("live --apply must run as root (normally through sudo)")
    exit_code = 0
    if args.command == "plan":
        plan = installer.plan_release()
        output: object = {
            "schema_version": SCHEMA_VERSION,
            "operation": "plan",
            "applied": False,
            "release_id": plan.release_id,
            "runtime_files": [record.path for record in plan.files],
            "root_files": dict(plan.root_files),
            "target_uid": layout.target_uid,
            "target_home": str(layout.user_root.parents[2]),
        }
    elif args.command == "status":
        output = installer.status()
    elif args.command == "install":
        if not args.apply:
            output = installer.preview_install()
        else:
            installer.validate_apply_prerequisites()
            result = installer.install(fault_at=args.fault_at)
            output = {
                "schema_version": SCHEMA_VERSION,
                "release_id": result.release_id,
                "changed": result.changed,
                "operation": result.operation,
                "applied": True,
            }
    elif args.command == "rollback":
        if not args.release_id:
            raise ReleaseError("rollback requires --release-id")
        if not args.apply:
            output = installer.preview_rollback(args.release_id)
        else:
            installer.validate_apply_prerequisites()
            result = installer.rollback(args.release_id, fault_at=args.fault_at)
            output = {
                "schema_version": SCHEMA_VERSION,
                "release_id": result.release_id,
                "changed": result.changed,
                "operation": result.operation,
                "applied": True,
            }
    elif args.command == "resume":
        result = installer.resume()
        output = {
            "schema_version": SCHEMA_VERSION,
            "release_id": result.release_id,
            "changed": result.changed,
            "operation": result.operation,
            "applied": True,
        }
    elif args.command == "abort":
        result = installer.abort_restore(args.restore_from, fault_at=args.fault_at)
        output = {
            "schema_version": SCHEMA_VERSION,
            "release_id": result.release_id,
            "changed": result.changed,
            "operation": result.operation,
            "applied": True,
        }
    elif args.command == "revalidate":
        result = installer.revalidate_boot()
        output = {
            "schema_version": SCHEMA_VERSION,
            "release_id": result.release_id,
            "changed": result.changed,
            "operation": result.operation,
            "applied": True,
        }
    elif args.command == "begin-release-qualification":
        if not args.release_id:
            raise ReleaseError("begin-release-qualification requires --release-id")
        result = installer.begin_release_qualification(release_id=args.release_id)
        output = {
            "schema_version": SCHEMA_VERSION,
            "release_id": result.release_id,
            "changed": result.changed,
            "operation": result.operation,
            "applied": True,
            "canary_nonce": (
                installer._read_rung_canary()["canary_nonce"]
                if _present(layout.rung_canary)
                else None
            ),
        }
    elif args.command == "begin-rung-canary":
        if not all(
            (
                args.release_id,
                args.rung,
                args.route_profile,
                args.contract_sha256,
                args.grok_release_id,
                args.model_id,
            )
        ):
            raise ReleaseError(
                "begin-rung-canary requires --release-id, --rung, "
                "--route-profile, --contract-sha256, --grok-release-id, and --model-id"
            )
        result = installer.begin_rung_canary(
            release_id=args.release_id,
            rung=args.rung,
            route_profile=args.route_profile,
            contract_sha256=args.contract_sha256,
            grok_release_id=args.grok_release_id,
            model_id=args.model_id,
        )
        output = {
            "schema_version": SCHEMA_VERSION,
            "release_id": result.release_id,
            "changed": result.changed,
            "operation": result.operation,
            "applied": True,
            "canary_nonce": installer._read_rung_canary()["canary_nonce"],
        }
    elif args.command == "canary-exec":
        if args.qualification_step is not None:
            if args.canary_arg:
                raise ReleaseError(
                    "fixed qualification does not accept free-form --canary-arg"
                )
            qualified = installer.qualification_exec(
                args.qualification_step,
                fault_at=args.fault_at,
            )
            output = {
                "schema_version": SCHEMA_VERSION,
                "release_id": qualified.release_id,
                "qualification_step": qualified.step,
                "status": qualified.status,
                "returncode": qualified.returncode,
                "result_sha256": qualified.result_sha256,
                "error_code": qualified.error_code,
                "error_sha256": qualified.error_sha256,
                "operation": "canary-exec",
                "applied": True,
            }
            exit_code = qualified.returncode
        else:
            if args.fault_at is not None:
                raise ReleaseError("manual canary-exec does not support --fault-at")
            result = installer.canary_exec(tuple(args.canary_arg))
            output = {
                "schema_version": SCHEMA_VERSION,
                "release_id": result.release_id,
                "rung": result.rung,
                "returncode": result.returncode,
                "run_id": result.run_id,
                "transcript_sha256": result.transcript_sha256,
                "transcript_kind": "manual",
                "operation": "canary-exec",
                "applied": True,
            }
            exit_code = result.returncode
    else:
        result = installer.promote_rung(
            args.evidence_file,
            fault_at=args.fault_at,
        )
        output = {
            "schema_version": SCHEMA_VERSION,
            "release_id": result.release_id,
            "changed": result.changed,
            "operation": result.operation,
            "applied": True,
        }
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return exit_code


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReleaseError as exc:
        print(f"install-release: {exc}", file=sys.stderr)
        raise SystemExit(2)
