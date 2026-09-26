"""ZELNX Connector SDK.

A standard framework for every platform connector (AWS, Azure, GCP, VMware,
K8s, HSM, PKI, Git, enterprise APIs, …):

    * ``ConnectorContext`` — per-run enforcement boundary (read-only, allowed
      methods, rate limit, maintenance window, exclusions, secret redaction).
    * ``BaseConnector``   — the interface a connector implements; ``run`` wraps
      ``scan`` with the guardrails so no connector can exceed its scope.
    * ``Observation``     — the single normalized emit envelope (source,
      timestamp, evidence, confidence, relationship).
    * ``register_connector`` / ``get_connector`` / ``available`` — registry so
      the platform resolves connectors by kind/method without hard-coded
      dispatchers.

Deterministic and no-AI: connectors return observed facts with confidence; the
platform correlates identity + evidence separately. Nothing is fabricated.
"""

from __future__ import annotations

from connector_sdk.base import BaseConnector
from connector_sdk.context import ConnectorContext, RateLimit, redact, scrub
from connector_sdk.observations import Observation, observations_to_json
from connector_sdk.registry import available, get_connector, register_connector

__all__ = [
    "BaseConnector",
    "ConnectorContext",
    "RateLimit",
    "redact",
    "scrub",
    "Observation",
    "observations_to_json",
    "available",
    "get_connector",
    "register_connector",
]
