"""ZELNX Universal Vendor Scanner — vendor-neutral crypto discovery.

Every vendor plugin (network, firewall, load balancer, cloud, PKI, HSM,
identity, database, middleware, OS, EDR, SIEM, DevOps, containers,
Kubernetes, SaaS) produces the same canonical output::

    Vendor-Specific Data → Vendor Plugin → Raw Observation → Evidence
    → Normalization → CryptoObservation → Canonical Asset

Read-only and metadata-only by contract: plugins parse configuration,
banners and API metadata — never key material, never secret values.
"""

from __future__ import annotations

from universal_vendor.models import (
    ConnectionResult,
    CryptoObservation,
    DetectionResult,
    LifecycleStatus,
    PqcCapability,
    ScanMode,
    UniversalObservation,
    VendorCapabilities,
    Visibility,
)
from universal_vendor.plugin import UniversalVendorPlugin

__all__ = [
    "ConnectionResult",
    "CryptoObservation",
    "DetectionResult",
    "LifecycleStatus",
    "PqcCapability",
    "ScanMode",
    "UniversalObservation",
    "UniversalVendorPlugin",
    "VendorCapabilities",
    "Visibility",
]
