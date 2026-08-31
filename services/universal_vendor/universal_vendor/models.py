"""Universal vendor scanner — shared data models.

These are the canonical, vendor-agnostic output shapes every plugin must
produce (spec §1 "every vendor plugin should produce the same canonical
output", §15 visibility statuses, §20 universal observation model,
§22 PQC capability statuses).
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ── Enums ────────────────────────────────────────────────────────────────

class VendorCategory(str, Enum):
    NETWORK = "network"
    FIREWALL = "firewall"
    LOAD_BALANCER = "load_balancer"
    CLOUD = "cloud"
    PKI = "pki"
    HSM = "hsm"
    IDENTITY = "identity"
    DATABASE = "database"
    MIDDLEWARE = "middleware"
    OS = "os"
    EDR = "edr"
    SIEM = "siem"
    DEVOPS = "devops"
    CONTAINER = "container"
    KUBERNETES = "kubernetes"
    SAAS = "saas"
    GENERIC = "generic"


class PluginStatus(str, Enum):
    STABLE = "STABLE"
    BETA = "BETA"
    EXPERIMENTAL = "EXPERIMENTAL"
    DEPRECATED = "DEPRECATED"
    DISABLED = "DISABLED"


class Visibility(str, Enum):
    """Spec §15 statuses — how confident we are in a SaaS/platform finding."""

    OBSERVED = "OBSERVED"
    API_VISIBLE = "API_VISIBLE"
    UNKNOWN = "UNKNOWN"
    NOT_SUPPORTED = "NOT_SUPPORTED"


class PqcCapability(str, Enum):
    """Spec §22 + §15 — vendor PQC readiness verdicts. Never inferred from a name.

    §22 scan-time verdicts: PQC_SUPPORTED, HYBRID_SUPPORTED, ROADMAP_DECLARED,
    NOT_SUPPORTED, UNKNOWN. §15 live capability states add PARTIALLY_SUPPORTED
    (e.g. PQ key exchange available but PQ signatures not yet).
    """

    PQC_SUPPORTED = "PQC_SUPPORTED"
    HYBRID_SUPPORTED = "HYBRID_SUPPORTED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    ROADMAP_DECLARED = "ROADMAP_DECLARED"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    UNKNOWN = "UNKNOWN"


class LifecycleStatus(str, Enum):
    """Spec §23 — support lifecycle verdicts."""

    SUPPORTED = "SUPPORTED"
    END_OF_SUPPORT = "END_OF_SUPPORT"
    END_OF_LIFE = "END_OF_LIFE"
    UNKNOWN = "UNKNOWN"


class ScanMode(str, Enum):
    """Spec §24 — universal vendor scan modes."""

    AUTO_DETECT = "AUTO_DETECT"
    INVENTORY_ONLY = "INVENTORY_ONLY"
    CRYPTO_DISCOVERY = "CRYPTO_DISCOVERY"
    CONFIGURATION_DISCOVERY = "CONFIGURATION_DISCOVERY"
    DEEP_DISCOVERY = "DEEP_DISCOVERY"
    CONTINUOUS_MONITORING = "CONTINUOUS_MONITORING"


class CryptoType(str, Enum):
    ALGORITHM = "algorithm"
    CERTIFICATE = "certificate"
    KEY = "key"
    PROTOCOL = "protocol"
    CONFIGURATION = "configuration"


class AssetType(str, Enum):
    ROUTER = "router"
    SWITCH = "switch"
    FIREWALL = "firewall"
    LOAD_BALANCER = "load_balancer"
    VPN = "vpn"
    CA = "ca"
    HSM = "hsm"
    IDENTITY_PROVIDER = "identity_provider"
    DATABASE = "database"
    MIDDLEWARE = "middleware"
    OS = "os"
    CONTAINER_REGISTRY = "container_registry"
    KUBERNETES = "kubernetes"
    APPLICATION = "application"
    SAAS = "saas"
    EDR = "edr"
    SIEM = "siem"
    CONTAINER = "container"
    OTHER = "other"


# ── Detection (spec §16) ─────────────────────────────────────────────────

class DetectionResult(BaseModel):
    detected_vendor: Optional[str] = None
    detected_product: Optional[str] = None
    detected_version: Optional[str] = None
    detection_method: Optional[str] = None  # e.g. "network_banner", "config", "ssh_banner"
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    signals: list[dict[str, Any]] = Field(default_factory=list)

    @property
    def detected(self) -> bool:
        return bool(self.detected_vendor) and self.confidence >= 0.5


class ConnectionResult(BaseModel):
    connected: bool = False
    message: str = ""
    details: dict[str, Any] = Field(default_factory=dict)


# ── Capability registry (spec §17) ───────────────────────────────────────

class VendorCapabilities(BaseModel):
    vendor: str
    product: str
    capabilities: list[str] = Field(default_factory=list)
    unsupported: list[str] = Field(default_factory=list)

    def supports(self, capability: str) -> bool:
        return capability in self.capabilities


# ── Universal observation (spec §20) ─────────────────────────────────────

class UniversalObservation(BaseModel):
    """Canonical vendor-agnostic observation. Vendor-specific fields are
    preserved verbatim in ``vendor_specific`` — nothing is lost during
    normalization."""

    # identity
    vendor: str
    product: str
    product_version: Optional[str] = None
    asset_id: Optional[str] = None
    asset_type: str = AssetType.OTHER.value
    environment: Optional[str] = None
    region: Optional[str] = None

    # crypto content
    crypto_type: str = CryptoType.ALGORITHM.value
    algorithm: Optional[str] = None
    key_type: Optional[str] = None
    key_size: Optional[int] = None
    curve: Optional[str] = None
    protocol: Optional[str] = None
    certificate: Optional[dict[str, Any]] = None
    configuration: Optional[dict[str, Any]] = None

    # provenance
    source: str = "unknown"
    evidence: dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(0.5, ge=0.0, le=1.0)
    visibility: str = Visibility.OBSERVED.value
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

    # vendor-specific data — preserved, never dropped (spec §20)
    vendor_specific: dict[str, Any] = Field(default_factory=dict)


class CryptoObservation(BaseModel):
    """Normalized crypto observation (spec §1 canonical asset)."""

    asset_id: Optional[str] = None
    vendor: str
    product: str
    product_version: Optional[str] = None
    algorithm: Optional[str] = None
    algorithm_family: Optional[str] = None
    key_type: Optional[str] = None
    key_size: Optional[int] = None
    curve: Optional[str] = None
    protocol: Optional[str] = None
    purpose: Optional[str] = None
    nist_status: Optional[str] = None
    quantum_vulnerable: Optional[bool] = None
    pqc_replacement: Optional[str] = None
    source: str = "unknown"
    evidence_id: Optional[str] = None
    content_hash: Optional[str] = None
    confidence: float = Field(0.5, ge=0.0, le=1.0)
    visibility: str = Visibility.OBSERVED.value
    vendor_specific: dict[str, Any] = Field(default_factory=dict)
