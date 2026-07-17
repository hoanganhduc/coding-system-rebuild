"""Pure command classification and immutable multi-session contract snapshots."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import os
from pathlib import Path
import pwd
import re
import shlex
import tomllib
from typing import Mapping, Sequence

from .contract import (
    PROTOCOL_VERSION,
    SCHEMA_VERSION,
    Endpoint,
    HomeEndpoint,
    ResourceLimits,
    RouteContract,
    RouteMode,
    StabilityPolicy,
    TimeoutPolicy,
    VpnPolicy,
    canonical_json_bytes,
)
from .grok_exec import GrokExecutableError, grok_release_id
from .secure_files import SecureFileError, read_secure_json


_TOKEN_RE = re.compile(r"^[A-Za-z0-9._:+/@-]{1,128}$")
_HOME_LABEL_RE = re.compile(r"^[A-Za-z0-9._:+@-]{1,120}$")
_BLOCKED_DEFAULT = (
    "AT BE BG HR CY CZ DK EE FI FR DE GR HU IE IT LV LT LU MT NL PL PT "
    "RO SK SI ES SE CN IR KP TM VE"
)


class ConfigurationError(ValueError):
    """The request cannot be represented by one safe v1 contract."""


class CommandKind(str, Enum):
    GATED = "gated"
    BARE = "bare"
    CONTROL = "control"
    RECOVERY = "recovery"
    MAINTENANCE = "maintenance"
    USAGE = "usage"


@dataclass(frozen=True, slots=True)
class Classification:
    kind: CommandKind
    grok_argv: tuple[str, ...]
    control: str | None = None
    route_mode: RouteMode = RouteMode.AUTO
    forced_host: str | None = None
    allow_direct: bool = True
    force_pick: bool = False


def gate_enabled(value: str | None) -> bool:
    """Only the literal value selected by the reviewed design enables v1."""

    return value == "1"


def _token(value: str, label: str) -> str:
    if _TOKEN_RE.fullmatch(value) is None:
        raise ConfigurationError(f"{label} contains unsupported characters")
    return value


def _home_label(value: str, label: str) -> str:
    if _HOME_LABEL_RE.fullmatch(value) is None:
        raise ConfigurationError(f"{label} contains unsupported characters")
    return value


def _positive_int(
    value: str | None, default: int, label: str, minimum: int, maximum: int
) -> int:
    if value is None or value == "":
        return default
    if not value.isdecimal():
        raise ConfigurationError(f"{label} must be an integer")
    parsed = int(value)
    if not minimum <= parsed <= maximum:
        raise ConfigurationError(f"{label} must be in [{minimum}, {maximum}]")
    return parsed


def classify(argv: Sequence[str]) -> Classification:
    """Classify without touching files, sockets, processes, or routes."""

    args = tuple(argv)
    if args and args[0] in {"-h", "--help", "help"}:
        return Classification(CommandKind.USAGE, args)
    if args and args[0] in {"inspect", "--version", "version"}:
        return Classification(CommandKind.BARE, args)
    if args and args[0] in {"status", "ip"}:
        if len(args) != 1:
            raise ConfigurationError(f"{args[0]} takes no operands")
        return Classification(CommandKind.CONTROL, (), control=args[0])
    if args and args[0] == "recover":
        if len(args) != 1:
            raise ConfigurationError("recover takes no operands")
        return Classification(CommandKind.RECOVERY, (), control="recover")
    if args and args[0] in {"stop", "iphone-setup"}:
        return Classification(CommandKind.MAINTENANCE, args, control=args[0])

    index = 0
    forced_host: str | None = None
    force_iphone = False
    force_vpn = False
    force_direct = False
    allow_direct = True
    force_pick = False
    while index < len(args):
        item = args[index]
        if item == "--host":
            if index + 1 >= len(args) or not args[index + 1]:
                raise ConfigurationError("--host requires a label")
            forced_host = _home_label(args[index + 1], "host label")
            index += 2
        elif item == "--iphone":
            force_iphone = True
            index += 1
        elif item == "--vpn":
            force_vpn = True
            index += 1
        elif item == "--direct":
            force_direct = True
            index += 1
        elif item == "--no-direct":
            allow_direct = False
            index += 1
        elif item == "--pick-model":
            force_pick = True
            index += 1
        elif item == "--":
            index += 1
            break
        else:
            break

    forced = sum((forced_host is not None, force_iphone, force_vpn, force_direct))
    if forced > 1:
        raise ConfigurationError(
            "choose only one of --host, --iphone, --vpn, or --direct"
        )
    remaining = args[index:]
    if remaining and remaining[0] in {"completions", "worktree", "leader"}:
        return Classification(CommandKind.BARE, remaining)
    for item in remaining:
        if item in {"--leader", "--no-leader", "--leader-socket"} or item.startswith(
            "--leader-socket="
        ):
            raise ConfigurationError(
                "leader controls are reserved by the multi-session wrapper"
            )
    route_mode = RouteMode.AUTO
    if forced_host is not None:
        route_mode = RouteMode.HOME
    elif force_iphone:
        route_mode = RouteMode.IPHONE
    elif force_vpn:
        route_mode = RouteMode.VPN
    elif force_direct:
        route_mode = RouteMode.DIRECT
    return Classification(
        CommandKind.GATED,
        remaining,
        route_mode=route_mode,
        forced_host=forced_host,
        allow_direct=allow_direct,
        force_pick=force_pick,
    )


def _cli_models(argv: Sequence[str]) -> tuple[str, ...]:
    values: list[str] = []
    index = 0
    while index < len(argv):
        item = argv[index]
        if item in {"-m", "--model"}:
            if index + 1 >= len(argv) or not argv[index + 1]:
                raise ConfigurationError(f"{item} requires a model ID")
            values.append(argv[index + 1])
            index += 2
            continue
        if item.startswith("--model="):
            value = item.split("=", 1)[1]
            if not value:
                raise ConfigurationError("--model requires a model ID")
            values.append(value)
        elif item.startswith("-m") and item != "-m":
            values.append(item[2:])
        index += 1
    return tuple(values)


def resolve_model(
    argv: Sequence[str], *, choice_path: Path, config_path: Path
) -> tuple[str, bool]:
    """Resolve one concrete model and report whether it was already in argv."""

    explicit = _cli_models(argv)
    if explicit:
        distinct = tuple(dict.fromkeys(explicit))
        if len(distinct) != 1:
            raise ConfigurationError("multiple different model IDs are not one contract")
        return _token(distinct[0], "model ID"), True

    try:
        chosen = choice_path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        chosen = ""
    if chosen:
        return _token(chosen, "remembered model ID"), False

    try:
        with config_path.open("rb") as handle:
            parsed = tomllib.load(handle)
    except FileNotFoundError:
        parsed = {}
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigurationError(f"cannot parse Grok config: {exc}") from exc
    models = parsed.get("models", {}) if isinstance(parsed, dict) else {}
    default = models.get("default", "") if isinstance(models, dict) else ""
    if not default and isinstance(parsed, dict):
        # Retain compatibility with the historical flat fixture/config shape,
        # while preferring Grok's current `[models].default` location.
        default = parsed.get("default", "")
    if isinstance(default, str) and default:
        return _token(default, "default model ID"), False
    raise ConfigurationError(
        "multi-session mode requires a concrete model; pass -m/--model or save one first"
    )


def parse_hosts(path: Path) -> tuple[tuple[str, str, str, int], ...]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return ()
    records: list[tuple[str, str, str, int]] = []
    labels: set[str] = set()
    for number, line in enumerate(lines, 1):
        try:
            fields = shlex.split(line, comments=True, posix=True)
        except ValueError as exc:
            raise ConfigurationError(f"hosts.conf:{number}: {exc}") from exc
        if not fields:
            continue
        if len(fields) != 4:
            raise ConfigurationError(f"hosts.conf:{number}: expected 4 fields")
        label, host, user, port_text = fields
        _home_label(label, f"hosts.conf:{number} label")
        _token(host, f"hosts.conf:{number} host")
        _token(user, f"hosts.conf:{number} user")
        port = _positive_int(port_text, 22, f"hosts.conf:{number} port", 1, 65_535)
        if label in labels:
            raise ConfigurationError(f"hosts.conf:{number}: duplicate label {label!r}")
        labels.add(label)
        records.append((label, host, user, port))
    return tuple(records)


def _phone_id(path: Path) -> str | None:
    try:
        value = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return None
    return _token(value, "iPhone node ID") if value else None


def _account_home() -> Path:
    try:
        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    except (KeyError, OSError) as exc:
        raise ConfigurationError(f"cannot resolve current account home: {exc}") from exc
    if not home.is_absolute():
        raise ConfigurationError("current account home is not absolute")
    return home


def _iphone_state_root(env: Mapping[str, str], account_home: Path) -> Path:
    fixed = account_home / ".local/state/grok-proxy/iphone"
    live = env.get("GROK_IPHONE_STATE_DIR")
    test_value = env.get("GROK_TEST_IPHONE_STATE_DIR")
    if test_value is not None:
        if env.get("GROK_TESTING") != "1":
            raise ConfigurationError(
                "GROK_TEST_IPHONE_STATE_DIR requires GROK_TESTING=1"
            )
        if live is not None:
            raise ConfigurationError(
                "choose only the live fixed iPhone state path or the test seam"
            )
        candidate = Path(test_value)
        if not candidate.is_absolute():
            raise ConfigurationError("test iPhone state path must be absolute")
        return candidate
    if live is not None and Path(live) != fixed:
        raise ConfigurationError(
            "GROK_IPHONE_STATE_DIR is fixed to the current account state directory"
        )
    return fixed


def _release_id(
    release_dir: Path, env: Mapping[str, str] | None = None
) -> str:
    manifest = release_dir / "release.json"
    try:
        value = read_secure_json(
            manifest,
            expected_uid=(
                os.getuid()
                if env is not None and env.get("GROK_TESTING") == "1"
                else 0
            ),
            expected_mode=0o444,
            maximum=1024 * 1024,
        )
        release = value["release_id"]
        return _token(release, "release ID")
    except FileNotFoundError:
        pass
    except (KeyError, TypeError, SecureFileError, ValueError, OSError) as exc:
        raise ConfigurationError(f"invalid release manifest: {exc}") from exc
    digest = hashlib.sha256()
    for relative in ("grok-remote", "egress.sh", "socks-netns.py", "vpngate-connect.sh"):
        path = release_dir / relative
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise ConfigurationError(f"cannot identify release file {path}: {exc}") from exc
        digest.update(relative.encode("ascii") + b"\0" + data + b"\0")
    return digest.hexdigest()


def _grok_release(grok_bin: Path, env: Mapping[str, str]) -> str:
    del env
    try:
        return grok_release_id(grok_bin)
    except (GrokExecutableError, OSError) as exc:
        raise ConfigurationError(f"cannot identify Grok binary: {exc}") from exc


def _countries(value: str, label: str) -> tuple[str, ...]:
    result = tuple(item.upper() for item in value.split() if item)
    if len(set(result)) != len(result) or any(not re.fullmatch(r"[A-Z]{2}", x) for x in result):
        raise ConfigurationError(f"{label} must be unique ISO alpha-2 codes")
    return result


def build_contract(
    classification: Classification,
    model_id: str,
    *,
    release_dir: Path,
    grok_bin: Path,
    env: Mapping[str, str],
    grok_release_id: str | None = None,
) -> RouteContract:
    """Parse mutable inputs once and return the epoch's immutable contract."""

    if classification.kind is not CommandKind.GATED:
        raise ConfigurationError("only gated commands have a route contract")
    model_id = _token(model_id, "model ID")
    home = _account_home()
    private_dir = release_dir if (release_dir / "hosts.conf").exists() else home / "grok-proxy"
    hosts = parse_hosts(private_dir / "hosts.conf")
    home_endpoints = tuple(
        HomeEndpoint(label=label, host=host, user=user, port=port)
        for label, host, user, port in hosts
    )
    iphone_root = _iphone_state_root(env, home)
    phone_id = _phone_id(iphone_root / "exit-node")
    if classification.route_mode is RouteMode.DIRECT:
        ladder = ("direct",)
    elif classification.route_mode is RouteMode.HOME:
        assert classification.forced_host is not None
        if classification.forced_host not in {record[0] for record in hosts}:
            raise ConfigurationError(f"unknown home host {classification.forced_host!r}")
        ladder = (f"home:{classification.forced_host}",)
    elif classification.route_mode is RouteMode.IPHONE:
        if phone_id is None:
            raise ConfigurationError("the iPhone route is not configured")
        ladder = ("iphone",)
    elif classification.route_mode is RouteMode.VPN:
        ladder = ("vpn",)
    else:
        mutable = [f"home:{endpoint.label}" for endpoint in home_endpoints]
        if phone_id is not None:
            mutable.append("iphone")
        mutable.append("vpn")
        if classification.allow_direct:
            mutable.append("direct")
        ladder = tuple(mutable)

    blocked = _countries(env.get("GROK_BLOCKED_CC", _BLOCKED_DEFAULT), "GROK_BLOCKED_CC")
    preferred = _countries(
        env.get("VPNGATE_COUNTRIES", env.get("VPNGATE_PREFER", "VN JP KR TH ID")),
        "VPNGATE_COUNTRIES",
    )
    allowed = tuple(country for country in preferred if country not in set(blocked))
    if not allowed:
        raise ConfigurationError("VPN country policy has no allowed country")

    public_port = _positive_int(env.get("GROK_PROXY_PORT"), 1080, "GROK_PROXY_PORT", 1, 65_535)
    private_text = env.get("GROK_PRIVATE_PORTS", "11080 11081")
    private_ports = tuple(
        _positive_int(item, 0, "GROK_PRIVATE_PORTS", 1, 65_535)
        for item in private_text.split()
    )
    if len(private_ports) < 2:
        raise ConfigurationError("GROK_PRIVATE_PORTS requires at least two ports")

    release_id = _release_id(release_dir, env)
    routing_snapshot = {
        "hosts": [endpoint.to_dict() for endpoint in home_endpoints],
        "phone_node_id": phone_id,
        "ladder": list(ladder),
        "blocked_countries": list(blocked),
        "allowed_countries": list(allowed),
    }
    routing_digest = hashlib.sha256(canonical_json_bytes(routing_snapshot)).hexdigest()
    limits = ResourceLimits(
        max_leases=_positive_int(env.get("GROK_MAX_LEASES"), 16, "GROK_MAX_LEASES", 1, 4096),
        max_control_connections=_positive_int(
            env.get("GROK_MAX_CONTROL_CONNECTIONS"), 32, "GROK_MAX_CONTROL_CONNECTIONS", 1, 4096
        ),
        max_frontend_streams=_positive_int(
            env.get("GROK_MAX_FRONTEND_STREAMS"), 256, "GROK_MAX_FRONTEND_STREAMS", 1, 65536
        ),
        max_packet_bytes=_positive_int(
            env.get("GROK_MAX_PACKET_BYTES"), 65_536, "GROK_MAX_PACKET_BYTES", 1024, 1_048_576
        ),
        per_stream_buffer_bytes=_positive_int(
            env.get("GROK_STREAM_BUFFER_BYTES"), 262_144, "GROK_STREAM_BUFFER_BYTES", 4096, 16_777_216
        ),
        total_buffer_bytes=_positive_int(
            env.get("GROK_TOTAL_BUFFER_BYTES"), 67_108_864, "GROK_TOTAL_BUFFER_BYTES", 4096, 4_294_967_296
        ),
    )
    if limits.total_buffer_bytes < limits.per_stream_buffer_bytes:
        raise ConfigurationError("total buffer limit is smaller than one stream buffer")
    return RouteContract(
        schema_version=SCHEMA_VERSION,
        protocol_version=PROTOCOL_VERSION,
        release_id=release_id,
        model_id=model_id,
        route_mode=classification.route_mode,
        forced_host=classification.forced_host,
        home_endpoints=home_endpoints,
        phone_node_id=phone_id,
        allow_direct=classification.allow_direct,
        ladder=ladder,
        routing_config_digest=routing_digest,
        probe_policy_version="models-via-private-v1",
        timeout_policy=TimeoutPolicy(
            connect_ms=_positive_int(env.get("GROK_CONNECT_TIMEOUT_MS"), 8_000, "connect timeout", 1, 3_600_000),
            probe_ms=_positive_int(env.get("GROK_PROBE_TIMEOUT_MS"), 90_000, "probe timeout", 1, 3_600_000),
            transition_ms=_positive_int(env.get("GROK_TRANSITION_TIMEOUT_MS"), 750_000, "transition timeout", 1, 3_600_000),
            stop_ms=_positive_int(env.get("GROK_STOP_TIMEOUT_MS"), 15_000, "stop timeout", 1, 3_600_000),
        ),
        stability_policy=StabilityPolicy(
            version="same-exit-v1",
            sample_count=_positive_int(env.get("GROK_VPN_STABILITY_CHECKS"), 3, "VPN stability checks", 1, 10),
            sample_interval_ms=_positive_int(env.get("GROK_STABILITY_INTERVAL_MS"), 1_000, "stability interval", 0, 3_600_000),
            require_same_exit=True,
        ),
        vpn_policy=VpnPolicy(
            namespace="grokvpn",
            max_tries=_positive_int(env.get("GROK_VPN_MAX_TRIES"), 6, "VPN tries", 1, 8),
            ranking_version="vpngate-score-uptime-v1",
            countries=allowed,
            blocked_countries=blocked,
        ),
        helper_release_ids=tuple(
            sorted((name, release_id) for name in ("broker", "relay", "sanitizer", "vpngate"))
        ),
        grok_release_id=(
            grok_release_id
            if grok_release_id is not None
            else _grok_release(grok_bin, env)
        ),
        public_endpoint=Endpoint("127.0.0.1", public_port),
        private_ports=private_ports,
        limits=limits,
    )


__all__ = [
    "Classification",
    "CommandKind",
    "ConfigurationError",
    "build_contract",
    "classify",
    "gate_enabled",
    "parse_hosts",
    "resolve_model",
]
