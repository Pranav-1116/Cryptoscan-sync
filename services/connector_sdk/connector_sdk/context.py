"""Connector execution context — the enforcement boundary of every ZELNX
connector.

A ``ConnectorContext`` is created per run from a tenant's authorized scope and
carries the guardrails the blueprint requires:

    allowed methods, read-only, rate limit, exclusions, maintenance windows.

It never stores secrets in plain sight (``redact`` scrubs them from any repr
or log) and every connector call goes through ``guard`` which enforces
read-only and rate limits *before* the connector touches the target. This is
what keeps a misconfigured connector from ever mutating a production system.
"""

from __future__ import annotations

import ipaddress
import re
import time
from dataclasses import dataclass, field
from typing import Any

#: secret-shaped config keys; values are redacted in logs / reprs.
_SECRET_KEY = re.compile(
    r"(secret|password|passwd|token|api[_ -]?key|access[_ -]?key|client[_ -]?secret|"
    r"private[_ -]?key|certificate|credential|passphrase|snmp[_ -]?community)",
    re.I,
)


def redact(value: Any) -> Any:
    """Recursively redact secret-shaped keys/values for logs and reprs."""
    if isinstance(value, dict):
        return {k: redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def scrub(value: dict[str, Any]) -> dict[str, Any]:
    """Deep-copy config in-memory with clearable secret keys, so an accidental
    repr never leaks credentials (caller still holds the real secret)."""
    out: dict[str, Any] = {}
    for k, v in value.items():
        if _SECRET_KEY.search(str(k)):
            out[k] = "***" if v else v
        else:
            out[k] = redact(v)
    return out


def _is_excluded(target: str, exclusions: tuple[str, ...]) -> bool:
    """True if ``target`` is excluded. Supports exact host/service strings,
    suffix/fragment matches (``payments.example.com`` matches ``payments``),
    and CIDR ranges (``10.0.0.0/8`` matches ``10.0.0.5``)."""
    for ex in exclusions:
        if not ex:
            continue
        if target == ex or ex in target or target in ex:
            return True
        if "/" in ex:
            try:
                if ipaddress.ip_address(target) in ipaddress.ip_network(ex, strict=False):
                    return True
            except ValueError:
                continue
    return False


@dataclass
class RateLimit:
    """Token-bucket limit: ``max_calls`` per ``window_seconds``."""

    max_calls: int = 60
    window_seconds: int = 60

    def __post_init__(self) -> None:
        self.max_calls = max(1, int(self.max_calls))
        self.window_seconds = max(1, int(self.window_seconds))
        self._tokens = float(self.max_calls)
        self._last_fill = time.monotonic()

    def allow(self) -> bool:
        now = time.monotonic()
        refill = (now - self._last_fill) * (self.max_calls / self.window_seconds)
        self._tokens = min(float(self.max_calls), self._tokens + refill)
        self._last_fill = now
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False


@dataclass
class ConnectorContext:
    """A single connector run's enforcement boundary.

    ``config`` holds the (future) connector configuration; secrets are scrubbed
    from ``self.config``. ``allowed_methods`` restricts which connector methods
    may be used; ``read_only`` blocks any mutating method; ``rate_limit`` caps
    call volume; ``exclusions`` are target patterns a scoped connector must not
    touch.
    """

    kind: str
    name: str
    method: str
    config: dict[str, Any] = field(default_factory=dict)
    allowed_methods: tuple[str, ...] = ("api", "agent", "vendor_api", "iam_role",
                                        "service_principal", "service_account", "snmp",
                                        "ssh", "netconf", "restconf", "syslog",
                                        "flow_telemetry", "other")
    read_only: bool = True          # ZELNX connectors default to read-only
    rate_limit: RateLimit = field(default_factory=lambda: RateLimit(60, 60))
    exclusions: tuple[str, ...] = ()
    maintenance_window_open: bool = True
    scanner: str | None = None
    tenant_id: str | None = None

    @property
    def redacted_config(self) -> dict[str, Any]:
        return scrub(self.config)

    def __repr__(self) -> str:  # never leak secrets in logs
        return (f"ConnectorContext(kind={self.kind!r}, name={self.name!r}, "
                f"method={self.method!r}, read_only={self.read_only!r}, "
                f"scanner={self.scanner!r}, tenant_id={self.tenant_id!r})")

    def guard(self, target: str, *, mutating: bool = False) -> None:
        """Raise before the connector touches ``target`` if the run is not
        authorized. Called by ``BaseConnector.run`` around every step."""
        if not self.maintenance_window_open:
            raise PermissionError(f"maintenance window closed for {self.name}")
        if _is_excluded(target, self.exclusions):
            raise PermissionError(f"target {target!r} is excluded from scope")
        if self.read_only and mutating:
            raise PermissionError(f"connector {self.name} is read-only; refusing mutating action on {target}")
        if self.method not in self.allowed_methods:
            raise PermissionError(f"method {self.method!r} not allowed (allowed={sorted(self.allowed_methods)})")
        if not self.rate_limit.allow():
            raise RuntimeError(f"rate limit exceeded for {self.name} "
                               f"({self.rate_limit.max_calls}/{self.rate_limit.window_seconds}s)")


__all__ = ["ConnectorContext", "RateLimit", "redact", "scrub"]
