"""Strict, canonical, typed contracts for a multi-session supervisor epoch."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
import hashlib
import json
import re
from typing import Any, Mapping


SCHEMA_VERSION = 1
PROTOCOL_VERSION = 1
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9._:+/@-]+$")
_HOME_LABEL_RE = re.compile(r"^[A-Za-z0-9._:+@-]+$")
_COUNTRY_RE = re.compile(r"^[A-Z]{2}$")
VPN_BROKER_BASE_TIMEOUT_MS = 120_000
VPN_BROKER_PER_ATTEMPT_MS = 30_000


class ContractValidationError(ValueError):
    """Raised when a contract is ambiguous, unsupported, or not strictly typed."""


class RouteMode(str, Enum):
    AUTO = "auto"
    DIRECT = "direct"
    HOME = "home"
    IPHONE = "iphone"
    VPN = "vpn"


def _fail(path: str, message: str) -> ContractValidationError:
    return ContractValidationError(f"{path}: {message}")


def _require_mapping(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise _fail(path, "expected an object")
    if any(type(key) is not str for key in value):
        raise _fail(path, "object keys must be strings")
    return value


def _require_exact_keys(
    value: Mapping[str, Any], expected: set[str], path: str
) -> None:
    actual = set(value)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing or extra:
        detail = []
        if missing:
            detail.append(f"missing {missing!r}")
        if extra:
            detail.append(f"unexpected {extra!r}")
        raise _fail(path, "; ".join(detail))


def _require_int(value: Any, path: str, minimum: int, maximum: int) -> int:
    if type(value) is not int:
        raise _fail(path, "expected an integer")
    if not minimum <= value <= maximum:
        raise _fail(path, f"must be in [{minimum}, {maximum}]")
    return value


def _require_bool(value: Any, path: str) -> bool:
    if type(value) is not bool:
        raise _fail(path, "expected a boolean")
    return value


def _require_text(
    value: Any,
    path: str,
    *,
    minimum: int = 1,
    maximum: int = 256,
    pattern: re.Pattern[str] | None = None,
) -> str:
    if type(value) is not str:
        raise _fail(path, "expected a string")
    if not minimum <= len(value) <= maximum:
        raise _fail(path, f"length must be in [{minimum}, {maximum}]")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise _fail(path, "control characters are forbidden")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise _fail(path, "contains unsupported characters")
    return value


def _require_optional_text(
    value: Any, path: str, *, maximum: int = 256
) -> str | None:
    if value is None:
        return None
    return _require_text(value, path, maximum=maximum, pattern=_TOKEN_RE)


def _require_digest(value: Any, path: str) -> str:
    value = _require_text(value, path, minimum=64, maximum=64)
    if _DIGEST_RE.fullmatch(value) is None:
        raise _fail(path, "expected a lowercase SHA-256 hex digest")
    return value


def _json_primitive(value: Any, path: str = "$") -> Any:
    if hasattr(value, "to_dict"):
        return _json_primitive(value.to_dict(), path)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        output = {}
        for key, item in value.items():
            if type(key) is not str:
                raise _fail(path, "canonical object keys must be strings")
            output[key] = _json_primitive(item, f"{path}.{key}")
        return output
    if isinstance(value, (tuple, list)):
        return [
            _json_primitive(item, f"{path}[{index}]")
            for index, item in enumerate(value)
        ]
    if value is None or type(value) in (str, int, bool):
        return value
    raise _fail(path, f"unsupported canonical type {type(value).__name__}")


def canonical_json_bytes(value: Any) -> bytes:
    """Return the one allowed UTF-8 representation for a typed record."""

    try:
        encoded = json.dumps(
            _json_primitive(value),
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise ContractValidationError(f"cannot encode canonical JSON: {exc}") from exc
    return encoded.encode("ascii")


@dataclass(frozen=True, slots=True)
class Endpoint:
    host: str
    port: int

    def __post_init__(self) -> None:
        _require_text(self.host, "endpoint.host", maximum=255)
        _require_int(self.port, "endpoint.port", 1, 65_535)

    def to_dict(self) -> dict[str, Any]:
        return {"host": self.host, "port": self.port}

    @classmethod
    def from_dict(cls, value: Any, path: str = "endpoint") -> "Endpoint":
        value = _require_mapping(value, path)
        _require_exact_keys(value, {"host", "port"}, path)
        return cls(
            host=_require_text(value["host"], f"{path}.host", maximum=255),
            port=_require_int(value["port"], f"{path}.port", 1, 65_535),
        )


@dataclass(frozen=True, slots=True)
class HomeEndpoint:
    """One ordered, immutable home-SSH routing record."""

    label: str
    host: str
    user: str
    port: int

    def __post_init__(self) -> None:
        _require_text(
            self.label,
            "home_endpoint.label",
            maximum=120,
            pattern=_HOME_LABEL_RE,
        )
        _require_text(
            self.host,
            "home_endpoint.host",
            maximum=255,
            pattern=_TOKEN_RE,
        )
        _require_text(
            self.user,
            "home_endpoint.user",
            maximum=128,
            pattern=_TOKEN_RE,
        )
        _require_int(self.port, "home_endpoint.port", 1, 65_535)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "label": self.label,
            "port": self.port,
            "user": self.user,
        }

    @classmethod
    def from_dict(
        cls, value: Any, path: str = "home_endpoint"
    ) -> "HomeEndpoint":
        value = _require_mapping(value, path)
        _require_exact_keys(value, {"label", "host", "user", "port"}, path)
        return cls(
            label=_require_text(
                value["label"],
                f"{path}.label",
                maximum=120,
                pattern=_HOME_LABEL_RE,
            ),
            host=_require_text(
                value["host"], f"{path}.host", maximum=255, pattern=_TOKEN_RE
            ),
            user=_require_text(
                value["user"], f"{path}.user", maximum=128, pattern=_TOKEN_RE
            ),
            port=_require_int(value["port"], f"{path}.port", 1, 65_535),
        )


@dataclass(frozen=True, slots=True)
class TimeoutPolicy:
    connect_ms: int
    probe_ms: int
    transition_ms: int
    stop_ms: int

    def __post_init__(self) -> None:
        for name, value in self.to_dict().items():
            _require_int(value, f"timeout_policy.{name}", 1, 3_600_000)

    def to_dict(self) -> dict[str, Any]:
        return {
            "connect_ms": self.connect_ms,
            "probe_ms": self.probe_ms,
            "stop_ms": self.stop_ms,
            "transition_ms": self.transition_ms,
        }

    @classmethod
    def from_dict(cls, value: Any, path: str = "timeout_policy") -> "TimeoutPolicy":
        value = _require_mapping(value, path)
        fields = {"connect_ms", "probe_ms", "transition_ms", "stop_ms"}
        _require_exact_keys(value, fields, path)
        parsed = {
            name: _require_int(value[name], f"{path}.{name}", 1, 3_600_000)
            for name in fields
        }
        return cls(**parsed)


@dataclass(frozen=True, slots=True)
class StabilityPolicy:
    version: str
    sample_count: int
    sample_interval_ms: int
    require_same_exit: bool

    def __post_init__(self) -> None:
        _require_text(
            self.version, "stability_policy.version", maximum=128, pattern=_TOKEN_RE
        )
        _require_int(
            self.sample_count, "stability_policy.sample_count", 1, 1_000
        )
        _require_int(
            self.sample_interval_ms,
            "stability_policy.sample_interval_ms",
            0,
            3_600_000,
        )
        _require_bool(
            self.require_same_exit, "stability_policy.require_same_exit"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "require_same_exit": self.require_same_exit,
            "sample_count": self.sample_count,
            "sample_interval_ms": self.sample_interval_ms,
            "version": self.version,
        }

    @classmethod
    def from_dict(
        cls, value: Any, path: str = "stability_policy"
    ) -> "StabilityPolicy":
        value = _require_mapping(value, path)
        fields = {
            "version",
            "sample_count",
            "sample_interval_ms",
            "require_same_exit",
        }
        _require_exact_keys(value, fields, path)
        return cls(
            version=_require_text(
                value["version"], f"{path}.version", maximum=128, pattern=_TOKEN_RE
            ),
            sample_count=_require_int(
                value["sample_count"], f"{path}.sample_count", 1, 1_000
            ),
            sample_interval_ms=_require_int(
                value["sample_interval_ms"],
                f"{path}.sample_interval_ms",
                0,
                3_600_000,
            ),
            require_same_exit=_require_bool(
                value["require_same_exit"], f"{path}.require_same_exit"
            ),
        )


@dataclass(frozen=True, slots=True)
class VpnPolicy:
    namespace: str
    max_tries: int
    ranking_version: str
    countries: tuple[str, ...]
    blocked_countries: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.namespace != "grokvpn":
            raise _fail("vpn_policy.namespace", "v1 requires the fixed grokvpn namespace")
        _require_int(self.max_tries, "vpn_policy.max_tries", 1, 8)
        _require_text(
            self.ranking_version,
            "vpn_policy.ranking_version",
            maximum=128,
            pattern=_TOKEN_RE,
        )
        for name, countries in (
            ("countries", self.countries),
            ("blocked_countries", self.blocked_countries),
        ):
            if type(countries) is not tuple:
                raise _fail(f"vpn_policy.{name}", "expected an immutable tuple")
            if len(set(countries)) != len(countries):
                raise _fail(f"vpn_policy.{name}", "duplicates are forbidden")
            for country in countries:
                _require_text(
                    country,
                    f"vpn_policy.{name}",
                    minimum=2,
                    maximum=2,
                    pattern=_COUNTRY_RE,
                )
        overlap = sorted(set(self.countries) & set(self.blocked_countries))
        if overlap:
            raise _fail("vpn_policy", f"allowed and blocked countries overlap: {overlap!r}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "blocked_countries": list(self.blocked_countries),
            "countries": list(self.countries),
            "max_tries": self.max_tries,
            "namespace": self.namespace,
            "ranking_version": self.ranking_version,
        }

    @classmethod
    def from_dict(cls, value: Any, path: str = "vpn_policy") -> "VpnPolicy":
        value = _require_mapping(value, path)
        fields = {
            "namespace",
            "max_tries",
            "ranking_version",
            "countries",
            "blocked_countries",
        }
        _require_exact_keys(value, fields, path)
        countries = value["countries"]
        blocked = value["blocked_countries"]
        if type(countries) is not list or type(blocked) is not list:
            raise _fail(path, "country fields must be arrays")
        return cls(
            namespace=_require_text(
                value["namespace"], f"{path}.namespace", maximum=64, pattern=_TOKEN_RE
            ),
            max_tries=_require_int(
                value["max_tries"], f"{path}.max_tries", 1, 8
            ),
            ranking_version=_require_text(
                value["ranking_version"],
                f"{path}.ranking_version",
                maximum=128,
                pattern=_TOKEN_RE,
            ),
            countries=tuple(countries),
            blocked_countries=tuple(blocked),
        )


@dataclass(frozen=True, slots=True)
class ResourceLimits:
    max_leases: int
    max_control_connections: int
    max_frontend_streams: int
    max_packet_bytes: int
    per_stream_buffer_bytes: int
    total_buffer_bytes: int

    def __post_init__(self) -> None:
        _require_int(self.max_leases, "limits.max_leases", 1, 4_096)
        _require_int(
            self.max_control_connections,
            "limits.max_control_connections",
            1,
            4_096,
        )
        if self.max_control_connections < self.max_leases + 2:
            raise _fail(
                "limits.max_control_connections",
                "must reserve at least two control connections beyond max_leases",
            )
        _require_int(
            self.max_frontend_streams, "limits.max_frontend_streams", 1, 65_536
        )
        _require_int(
            self.max_packet_bytes, "limits.max_packet_bytes", 1_024, 1_048_576
        )
        _require_int(
            self.per_stream_buffer_bytes,
            "limits.per_stream_buffer_bytes",
            4_096,
            16_777_216,
        )
        _require_int(
            self.total_buffer_bytes,
            "limits.total_buffer_bytes",
            self.per_stream_buffer_bytes,
            4_294_967_296,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_control_connections": self.max_control_connections,
            "max_frontend_streams": self.max_frontend_streams,
            "max_leases": self.max_leases,
            "max_packet_bytes": self.max_packet_bytes,
            "per_stream_buffer_bytes": self.per_stream_buffer_bytes,
            "total_buffer_bytes": self.total_buffer_bytes,
        }

    @classmethod
    def from_dict(cls, value: Any, path: str = "limits") -> "ResourceLimits":
        value = _require_mapping(value, path)
        fields = {
            "max_leases",
            "max_control_connections",
            "max_frontend_streams",
            "max_packet_bytes",
            "per_stream_buffer_bytes",
            "total_buffer_bytes",
        }
        _require_exact_keys(value, fields, path)
        parsed = {}
        bounds = {
            "max_leases": (1, 4_096),
            "max_control_connections": (1, 4_096),
            "max_frontend_streams": (1, 65_536),
            "max_packet_bytes": (1_024, 1_048_576),
            "per_stream_buffer_bytes": (4_096, 16_777_216),
            "total_buffer_bytes": (4_096, 4_294_967_296),
        }
        for name, (minimum, maximum) in bounds.items():
            parsed[name] = _require_int(
                value[name], f"{path}.{name}", minimum, maximum
            )
        return cls(**parsed)


@dataclass(frozen=True, slots=True)
class RouteContract:
    schema_version: int
    protocol_version: int
    release_id: str
    model_id: str
    route_mode: RouteMode
    forced_host: str | None
    home_endpoints: tuple[HomeEndpoint, ...]
    phone_node_id: str | None
    allow_direct: bool
    ladder: tuple[str, ...]
    routing_config_digest: str
    probe_policy_version: str
    timeout_policy: TimeoutPolicy
    stability_policy: StabilityPolicy
    vpn_policy: VpnPolicy
    helper_release_ids: tuple[tuple[str, str], ...]
    grok_release_id: str
    public_endpoint: Endpoint
    private_ports: tuple[int, ...]
    limits: ResourceLimits

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise _fail("schema_version", f"unsupported value {self.schema_version!r}")
        if self.protocol_version != PROTOCOL_VERSION:
            raise _fail(
                "protocol_version", f"unsupported value {self.protocol_version!r}"
            )
        _require_text(
            self.release_id, "release_id", maximum=128, pattern=_TOKEN_RE
        )
        _require_text(self.model_id, "model_id", maximum=128, pattern=_TOKEN_RE)
        if not isinstance(self.route_mode, RouteMode):
            raise _fail("route_mode", "expected a RouteMode")
        _require_optional_text(self.forced_host, "forced_host", maximum=128)
        if self.forced_host is not None:
            _require_text(
                self.forced_host,
                "forced_host",
                maximum=120,
                pattern=_HOME_LABEL_RE,
            )
        if type(self.home_endpoints) is not tuple:
            raise _fail("home_endpoints", "expected an immutable tuple")
        labels: list[str] = []
        for index, endpoint in enumerate(self.home_endpoints):
            if not isinstance(endpoint, HomeEndpoint):
                raise _fail(
                    f"home_endpoints[{index}]", "expected a HomeEndpoint"
                )
            labels.append(endpoint.label)
        if len(set(labels)) != len(labels):
            raise _fail("home_endpoints", "duplicate labels are forbidden")
        _require_optional_text(self.phone_node_id, "phone_node_id", maximum=256)
        _require_bool(self.allow_direct, "allow_direct")

        if self.route_mode is RouteMode.HOME and self.forced_host is None:
            raise _fail("forced_host", "a forced home route requires a host label")
        if self.route_mode is not RouteMode.HOME and self.forced_host is not None:
            raise _fail("forced_host", "is valid only with route_mode=home")
        if self.route_mode is RouteMode.IPHONE and self.phone_node_id is None:
            raise _fail("phone_node_id", "a forced iPhone route requires a stable node ID")
        if self.forced_host is not None and self.forced_host not in labels:
            raise _fail("forced_host", "does not name a frozen home endpoint")
        if self.route_mode is RouteMode.DIRECT and not self.allow_direct:
            raise _fail("allow_direct", "cannot be false for a forced direct route")

        if type(self.ladder) is not tuple or not self.ladder:
            raise _fail("ladder", "expected a nonempty immutable tuple")
        if len(set(self.ladder)) != len(self.ladder):
            raise _fail("ladder", "duplicates are forbidden")
        for rung in self.ladder:
            _require_text(rung, "ladder", maximum=128)
            if rung not in {"direct", "iphone", "vpn"} and not rung.startswith("home:"):
                raise _fail("ladder", f"unsupported rung {rung!r}")
            if rung.startswith("home:"):
                label = _require_text(
                    rung.removeprefix("home:"),
                    "ladder.home_label",
                    maximum=120,
                    pattern=_HOME_LABEL_RE,
                )
                if label not in labels:
                    raise _fail("ladder", f"home endpoint {label!r} is not frozen")
        if "iphone" in self.ladder and self.phone_node_id is None:
            raise _fail(
                "phone_node_id", "an iPhone ladder rung requires a stable node ID"
            )
        if self.route_mode is RouteMode.AUTO:
            ladder_labels = tuple(
                rung.removeprefix("home:")
                for rung in self.ladder
                if rung.startswith("home:")
            )
            label_positions = {label: index for index, label in enumerate(labels)}
            positions = tuple(label_positions[label] for label in ladder_labels)
            if positions != tuple(sorted(positions)):
                raise _fail(
                    "home_endpoints",
                    "auto-mode ladder must preserve frozen home endpoint order",
                )

        _require_digest(self.routing_config_digest, "routing_config_digest")
        _require_text(
            self.probe_policy_version,
            "probe_policy_version",
            maximum=128,
            pattern=_TOKEN_RE,
        )
        if not isinstance(self.timeout_policy, TimeoutPolicy):
            raise _fail("timeout_policy", "expected TimeoutPolicy")
        if not isinstance(self.stability_policy, StabilityPolicy):
            raise _fail("stability_policy", "expected StabilityPolicy")
        if not isinstance(self.vpn_policy, VpnPolicy):
            raise _fail("vpn_policy", "expected VpnPolicy")
        if "vpn" in self.ladder:
            # One outer provider deadline must contain the broker's complete
            # durable attempt envelope and one full successful qualification
            # (exit samples plus the model probe).  Later rejected candidates
            # share that same absolute deadline and cannot restart it.
            broker_ms = (
                VPN_BROKER_BASE_TIMEOUT_MS
                + VPN_BROKER_PER_ATTEMPT_MS * self.vpn_policy.max_tries
            )
            qualification_ms = (
                (self.stability_policy.sample_count + 1)
                * self.timeout_policy.probe_ms
                + max(0, self.stability_policy.sample_count - 1)
                * self.stability_policy.sample_interval_ms
            )
            required_transition_ms = max(
                self.timeout_policy.connect_ms,
                self.timeout_policy.stop_ms,
                broker_ms + qualification_ms,
            )
            if self.timeout_policy.transition_ms < required_transition_ms:
                raise _fail(
                    "timeout_policy.transition_ms",
                    "must be at least "
                    f"{required_transition_ms} for the VPN broker and one "
                    "complete qualification",
                )

        if type(self.helper_release_ids) is not tuple:
            raise _fail("helper_release_ids", "expected an immutable tuple")
        if tuple(sorted(self.helper_release_ids)) != self.helper_release_ids:
            raise _fail("helper_release_ids", "entries must be sorted by helper name")
        names = []
        for item in self.helper_release_ids:
            if type(item) is not tuple or len(item) != 2:
                raise _fail("helper_release_ids", "expected (name, release) pairs")
            name, release = item
            _require_text(name, "helper_release_ids.name", maximum=64, pattern=_TOKEN_RE)
            _require_text(
                release, "helper_release_ids.release", maximum=128, pattern=_TOKEN_RE
            )
            names.append(name)
        if len(set(names)) != len(names):
            raise _fail("helper_release_ids", "duplicate helper names are forbidden")

        _require_text(
            self.grok_release_id, "grok_release_id", maximum=128, pattern=_TOKEN_RE
        )
        if not isinstance(self.public_endpoint, Endpoint):
            raise _fail("public_endpoint", "expected Endpoint")
        if self.public_endpoint.host != "127.0.0.1":
            raise _fail("public_endpoint.host", "v1 requires 127.0.0.1")
        if type(self.private_ports) is not tuple or len(self.private_ports) < 2:
            raise _fail("private_ports", "at least two immutable ports are required")
        for port in self.private_ports:
            _require_int(port, "private_ports", 1, 65_535)
        if len(set(self.private_ports)) != len(self.private_ports):
            raise _fail("private_ports", "duplicates are forbidden")
        if self.public_endpoint.port in self.private_ports:
            raise _fail("private_ports", "must not contain the public frontend port")
        if not isinstance(self.limits, ResourceLimits):
            raise _fail("limits", "expected ResourceLimits")

    def to_dict(self) -> dict[str, Any]:
        return {
            "allow_direct": self.allow_direct,
            "forced_host": self.forced_host,
            "grok_release_id": self.grok_release_id,
            "helper_release_ids": dict(self.helper_release_ids),
            "home_endpoints": [item.to_dict() for item in self.home_endpoints],
            "ladder": list(self.ladder),
            "limits": self.limits.to_dict(),
            "model_id": self.model_id,
            "phone_node_id": self.phone_node_id,
            "private_ports": list(self.private_ports),
            "probe_policy_version": self.probe_policy_version,
            "protocol_version": self.protocol_version,
            "public_endpoint": self.public_endpoint.to_dict(),
            "release_id": self.release_id,
            "route_mode": self.route_mode.value,
            "routing_config_digest": self.routing_config_digest,
            "schema_version": self.schema_version,
            "stability_policy": self.stability_policy.to_dict(),
            "timeout_policy": self.timeout_policy.to_dict(),
            "vpn_policy": self.vpn_policy.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: Any, path: str = "contract") -> "RouteContract":
        value = _require_mapping(value, path)
        fields = {
            "schema_version",
            "protocol_version",
            "release_id",
            "model_id",
            "route_mode",
            "forced_host",
            "home_endpoints",
            "phone_node_id",
            "allow_direct",
            "ladder",
            "routing_config_digest",
            "probe_policy_version",
            "timeout_policy",
            "stability_policy",
            "vpn_policy",
            "helper_release_ids",
            "grok_release_id",
            "public_endpoint",
            "private_ports",
            "limits",
        }
        _require_exact_keys(value, fields, path)
        route_text = _require_text(
            value["route_mode"], f"{path}.route_mode", maximum=16
        )
        try:
            route_mode = RouteMode(route_text)
        except ValueError as exc:
            raise _fail(f"{path}.route_mode", f"unsupported value {route_text!r}") from exc
        ladder = value["ladder"]
        home_endpoints = value["home_endpoints"]
        private_ports = value["private_ports"]
        helpers = _require_mapping(value["helper_release_ids"], f"{path}.helper_release_ids")
        if (
            type(ladder) is not list
            or type(home_endpoints) is not list
            or type(private_ports) is not list
        ):
            raise _fail(path, "home_endpoints, ladder, and private_ports must be arrays")
        helper_pairs = []
        for name, release in helpers.items():
            helper_pairs.append(
                (
                    _require_text(
                        name,
                        f"{path}.helper_release_ids.name",
                        maximum=64,
                        pattern=_TOKEN_RE,
                    ),
                    _require_text(
                        release,
                        f"{path}.helper_release_ids.{name}",
                        maximum=128,
                        pattern=_TOKEN_RE,
                    ),
                )
            )
        return cls(
            schema_version=_require_int(
                value["schema_version"], f"{path}.schema_version", 1, 2**31 - 1
            ),
            protocol_version=_require_int(
                value["protocol_version"],
                f"{path}.protocol_version",
                1,
                2**31 - 1,
            ),
            release_id=_require_text(
                value["release_id"],
                f"{path}.release_id",
                maximum=128,
                pattern=_TOKEN_RE,
            ),
            model_id=_require_text(
                value["model_id"],
                f"{path}.model_id",
                maximum=128,
                pattern=_TOKEN_RE,
            ),
            route_mode=route_mode,
            forced_host=_require_optional_text(
                value["forced_host"], f"{path}.forced_host", maximum=128
            ),
            home_endpoints=tuple(
                HomeEndpoint.from_dict(item, f"{path}.home_endpoints[{index}]")
                for index, item in enumerate(home_endpoints)
            ),
            phone_node_id=_require_optional_text(
                value["phone_node_id"], f"{path}.phone_node_id", maximum=256
            ),
            allow_direct=_require_bool(
                value["allow_direct"], f"{path}.allow_direct"
            ),
            ladder=tuple(ladder),
            routing_config_digest=_require_digest(
                value["routing_config_digest"], f"{path}.routing_config_digest"
            ),
            probe_policy_version=_require_text(
                value["probe_policy_version"],
                f"{path}.probe_policy_version",
                maximum=128,
                pattern=_TOKEN_RE,
            ),
            timeout_policy=TimeoutPolicy.from_dict(
                value["timeout_policy"], f"{path}.timeout_policy"
            ),
            stability_policy=StabilityPolicy.from_dict(
                value["stability_policy"], f"{path}.stability_policy"
            ),
            vpn_policy=VpnPolicy.from_dict(
                value["vpn_policy"], f"{path}.vpn_policy"
            ),
            helper_release_ids=tuple(sorted(helper_pairs)),
            grok_release_id=_require_text(
                value["grok_release_id"],
                f"{path}.grok_release_id",
                maximum=128,
                pattern=_TOKEN_RE,
            ),
            public_endpoint=Endpoint.from_dict(
                value["public_endpoint"], f"{path}.public_endpoint"
            ),
            private_ports=tuple(private_ports),
            limits=ResourceLimits.from_dict(value["limits"], f"{path}.limits"),
        )

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    def digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def home_endpoint(self, label: str) -> HomeEndpoint | None:
        """Return the frozen home endpoint for ``label``, if present."""

        _require_text(
            label, "home_endpoint.label", maximum=120, pattern=_HOME_LABEL_RE
        )
        for endpoint in self.home_endpoints:
            if endpoint.label == label:
                return endpoint
        return None

    def semantic_differences(self, other: "RouteContract") -> tuple[str, ...]:
        if not isinstance(other, RouteContract):
            raise TypeError("other must be a RouteContract")
        differences: list[str] = []

        def compare(left: Any, right: Any, path: str) -> None:
            if isinstance(left, Mapping) and isinstance(right, Mapping):
                if set(left) != set(right):
                    differences.append(path)
                    return
                for key in sorted(left):
                    compare(left[key], right[key], f"{path}.{key}" if path else key)
                return
            if isinstance(left, list) and isinstance(right, list):
                if left != right:
                    differences.append(path)
                return
            if left != right:
                differences.append(path)

        compare(self.to_dict(), other.to_dict(), "")
        return tuple(differences)


def reconstruct_original_contract(contract: RouteContract) -> RouteContract:
    """Rebuild the pre-qualification route ladder from frozen route inputs.

    Qualification narrows only ``ladder``.  All other routing inputs remain in
    the runtime contract so the supervisor can independently recover and hash
    the exact contract that the root canary authorized.
    """

    if not isinstance(contract, RouteContract):
        raise _fail("contract", "expected a RouteContract")
    if contract.route_mode is RouteMode.DIRECT:
        original = ("direct",)
    elif contract.route_mode is RouteMode.HOME:
        assert contract.forced_host is not None
        original = (f"home:{contract.forced_host}",)
    elif contract.route_mode is RouteMode.IPHONE:
        original = ("iphone",)
    elif contract.route_mode is RouteMode.VPN:
        original = ("vpn",)
    else:
        mutable = [f"home:{endpoint.label}" for endpoint in contract.home_endpoints]
        if contract.phone_node_id is not None:
            mutable.append("iphone")
        mutable.append("vpn")
        if contract.allow_direct:
            mutable.append("direct")
        original = tuple(mutable)

    positions: list[int] = []
    for rung in contract.ladder:
        try:
            positions.append(original.index(rung))
        except ValueError as exc:
            raise _fail(
                "ladder", f"rung {rung!r} is not authorized by frozen route inputs"
            ) from exc
    if positions != sorted(positions):
        raise _fail("ladder", "filtered rungs do not preserve original route order")
    return replace(contract, ladder=original)


def qualification_route_profile_matches(
    contract: RouteContract,
    route_profile: str,
    rung: str,
) -> bool:
    """Return whether one closed canary profile binds this contract and rung."""

    try:
        original = reconstruct_original_contract(contract)
    except ContractValidationError:
        return False
    if rung not in original.ladder:
        return False
    if original.route_mode is RouteMode.DIRECT:
        return route_profile == "direct" and rung == "direct"
    if original.route_mode is RouteMode.HOME:
        expected = f"home:{original.forced_host}"
        return route_profile == expected and rung == expected
    if original.route_mode is RouteMode.IPHONE:
        return route_profile == "iphone" and rung == "iphone"
    if original.route_mode is RouteMode.VPN:
        return route_profile == "vpn" and rung == "vpn"
    expected = "auto" if original.allow_direct else "auto-no-direct"
    return route_profile == expected


__all__ = [
    "PROTOCOL_VERSION",
    "SCHEMA_VERSION",
    "ContractValidationError",
    "Endpoint",
    "HomeEndpoint",
    "ResourceLimits",
    "RouteContract",
    "RouteMode",
    "StabilityPolicy",
    "TimeoutPolicy",
    "VpnPolicy",
    "canonical_json_bytes",
    "qualification_route_profile_matches",
    "reconstruct_original_contract",
]
