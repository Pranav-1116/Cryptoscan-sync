"""ZELNX Cloud Discovery Engine — multi-cloud crypto discovery (enterprise).

A read-only, evidence-chained discovery engine covering organization
hierarchy, full asset inventory, cryptographic keys, certificates, PKI,
encryption state, network cryptography, TLS, Kubernetes, serverless,
secret references, IAM access, dependency graphs, cross-cloud
relationships, posture, PQC readiness, migration simulation, cost,
compliance, drift, event-driven monitoring and evidence collection —
across AWS, Azure and GCP with fully injectable provider adapters.

Entry point: :class:`ZelixCloudDiscoveryEngine`.
"""

from __future__ import annotations

from cloud_scanner.enterprise.engine import DiscoveryReport, ZelixCloudDiscoveryEngine
from cloud_scanner.enterprise.providers import ProviderAdapter, fake_provider
from cloud_scanner.enterprise.scan_modes import (
    DEFAULT_MODES,
    SCAN_MODES,
    CloudScanMode,
    describe,
    validate_modes,
)

__all__ = [
    "ZelixCloudDiscoveryEngine",
    "DiscoveryReport",
    "ProviderAdapter",
    "fake_provider",
    "CloudScanMode",
    "SCAN_MODES",
    "DEFAULT_MODES",
    "validate_modes",
    "describe",
]
