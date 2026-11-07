"""Stack settings and honest connection status (deploy/stack/).

Every backend in the platform table has a typed setting here, and a probe
that reports exactly three states per backend:

- ``UNCONFIGURED`` — no setting present: nothing is claimed;
- ``REACHABLE``   — a socket probe SUCCEEDED just now: the endpoint
  answered, which is reachability, not a health or qualification claim;
- ``UNREACHABLE`` — the probe failed: named as such, never drawn as zeros
  or as a quiet success.

Configured settings are not connected backends; a reachable socket is not
a qualified integration. This module measures reachability only.
"""

from __future__ import annotations

import os
import socket
from typing import Any, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field


UNCONFIGURED = "UNCONFIGURED"
REACHABLE = "REACHABLE"
UNREACHABLE = "UNREACHABLE"


class BackendSetting(BaseModel):
    name: str
    role: str
    env_var: str
    value: Optional[str] = None


#: (name, role in the platform table, environment variable)
BACKENDS: tuple[tuple[str, str, str], ...] = (
    ("PostgreSQL", "TRUTH", "DATABASE_URL"),
    ("Neo4j", "GRAPH", "NEO4J_URI"),
    ("Redis", "SPEED", "REDIS_URL"),
    ("Celery", "JOBS", "CELERY_BROKER_URL"),
    ("Kafka", "EVENTS", "KAFKA_BOOTSTRAP_SERVERS"),
    ("MinIO", "EVIDENCE", "MINIO_ENDPOINT"),
    ("OpenSearch", "SEARCH", "OPENSEARCH_URL"),
    ("Prometheus", "METRICS", "PROMETHEUS_URL"),
    ("Grafana", "MONITORING", "GRAFANA_URL"),
    ("OpenTelemetry", "TRACING", "OTEL_EXPORTER_OTLP_ENDPOINT"),
    ("Vault", "SECRETS", "VAULT_ADDR"),
    ("Envoy", "GATEWAY", "ENVOY_ADMIN_URL"),
    ("OIDC", "IDENTITY", "OIDC_ISSUER_URL"),
)


def settings(environ: dict[str, str] | None = None) -> list[BackendSetting]:
    env = os.environ if environ is None else environ
    out: list[BackendSetting] = []
    for name, role, var in BACKENDS:
        value = str(env.get(var) or "").strip() or None
        out.append(BackendSetting(name=name, role=role, env_var=var, value=value))
    return out


def _host_port(value: str) -> tuple[str, int] | None:
    """Parse an endpoint into (host, port) for a socket probe."""
    candidate = value.split(",")[0].strip()  # kafka: take the first broker
    if "://" not in candidate:
        candidate = f"tcp://{candidate}"
    parsed = urlparse(candidate)
    if not parsed.hostname or " " in parsed.hostname or "%" in parsed.hostname:
        return None
    port = parsed.port or {"postgres": 5432, "postgresql": 5432, "bolt": 7687,
                           "redis": 6379, "http": 80, "https": 443,
                           "tcp": 9092}.get(parsed.scheme or "tcp", 80)
    return parsed.hostname, int(port)


def probe_one(name: str, role: str, env_var: str,
              value: Optional[str], *,
              timeout: float = 1.0,
              connect: Any = None) -> dict[str, Any]:
    row = {"name": name, "role": role, "env_var": env_var,
           "endpoint": value, "status": UNCONFIGURED,
           "detail": "no setting present: nothing is claimed"}
    if not value:
        return row
    target = _host_port(value)
    if target is None:
        row["status"] = UNREACHABLE
        row["detail"] = f"configured value {value!r} has no probeable host"
        return row
    attempt = connect or _socket_connect
    try:
        attempt(target[0], target[1], timeout)
    except OSError as exc:
        row["status"] = UNREACHABLE
        row["detail"] = (f"socket probe to {target[0]}:{target[1]} failed "
                         f"({exc.strerror or exc}): named unreachable, never "
                         "drawn as a quiet success")
        return row
    row["status"] = REACHABLE
    row["detail"] = (f"socket probe to {target[0]}:{target[1]} succeeded: "
                     "reachable now — reachability, not a health or "
                     "qualification claim")
    return row


def _socket_connect(host: str, port: int, timeout: float) -> None:
    with socket.create_connection((host, port), timeout=timeout):
        pass


class StackStatus(BaseModel):
    schema: str = "cryptoscan.stack-status/1"
    checked: list[dict[str, Any]] = Field(default_factory=list)
    note: str = ("configured settings are not connected backends; a reachable "
                 "socket is not a qualified integration")


def probe(*, environ: dict[str, str] | None = None,
          timeout: float = 1.0, connect: Any = None) -> StackStatus:
    rows = [probe_one(s.name, s.role, s.env_var, s.value,
                      timeout=timeout, connect=connect)
            for s in settings(environ)]
    return StackStatus(checked=rows)
