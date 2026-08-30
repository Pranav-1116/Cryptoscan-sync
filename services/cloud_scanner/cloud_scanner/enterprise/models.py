"""ZELNX Cloud Discovery Engine — shared discovery model.

The model mirrors the cloud estate faithfully but **never carries key
material or secret values** — only metadata and references.  Every record
carries an ``evidence`` block (source provider, account, API source,
timestamp, normalization version, confidence) that the evidence chain
hashes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

NORMALIZATION_VERSION = "zelix-1.0"


def parse_iso(text: Any):
    """Parse an ISO-8601 string (Z suffix tolerated) without third-party deps."""
    from datetime import datetime

    if not text:
        return None
    try:
        return datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def _clean(d: dict[str, Any] | None) -> dict[str, Any]:
    return {k: v for k, v in (d or {}).items() if v is not None}


@dataclass
class EvidenceSource:
    """Provenance for a discovery observation (spec §22)."""

    source_provider: str = ""
    account: str | None = None
    api_source: str = ""
    timestamp: str = ""
    normalization_version: str = NORMALIZATION_VERSION
    confidence: str = "MEDIUM"  # MEASURED / PROVIDER_REPORTED / ESTIMATED / ASSUMED

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_provider": self.source_provider,
            "account": self.account,
            "api_source": self.api_source,
            "timestamp": self.timestamp,
            "normalization_version": self.normalization_version,
            "confidence": self.confidence,
        }


@dataclass
class CloudAccount:
    """One AWS account / Azure subscription / GCP project (spec §1)."""

    provider: str  # aws | azure | gcp
    account_id: str
    name: str = ""
    org_path: list[str] = field(default_factory=list)  # org -> business unit
    status: str = "ACTIVE"
    metadata: dict[str, Any] = field(default_factory=dict)
    regions: list["CloudRegion"] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "account_id": self.account_id,
            "name": self.name,
            "org_path": list(self.org_path),
            "status": self.status,
            "metadata": dict(self.metadata),
            "regions": [region.to_dict() for region in self.regions],
        }


@dataclass
class CloudRegion:
    """A region (and its zones) inside a cloud account."""

    name: str
    zones: list[str] = field(default_factory=list)
    resource_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "zones": list(self.zones),
            "resource_count": self.resource_count,
        }


@dataclass
class Workload:
    """A compute workload with its full identity context (spec §2)."""

    workload_id: str
    cloud_provider: str
    account: str = ""
    subscription: str = ""
    project: str = ""
    region: str = ""
    zone: str = ""
    environment: str = ""
    network: str = ""
    application: str = ""
    owner: str = ""
    runtime: str = ""
    os: str = ""
    container: str = ""
    crypto_usage: list[str] = field(default_factory=list)
    certificate_usage: list[str] = field(default_factory=list)
    key_dependencies: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    evidence: EvidenceSource = field(default_factory=EvidenceSource)

    def to_dict(self) -> dict[str, Any]:
        return {
            "workload_id": self.workload_id,
            "cloud_provider": self.cloud_provider,
            "account": self.account,
            "subscription": self.subscription,
            "project": self.project,
            "region": self.region,
            "zone": self.zone,
            "environment": self.environment,
            "network": self.network,
            "application": self.application,
            "owner": self.owner,
            "runtime": self.runtime,
            "os": self.os,
            "container": self.container,
            "crypto_usage": list(self.crypto_usage),
            "certificate_usage": list(self.certificate_usage),
            "key_dependencies": list(self.key_dependencies),
            "metadata": dict(self.metadata),
            "evidence": self.evidence.to_dict(),
        }


@dataclass
class CryptoKey:
    """Cryptographic key metadata — never the key material (spec §3)."""

    provider: str  # aws | azure | gcp
    account: str = ""
    region: str = ""
    key_id: str = ""
    name: str = ""
    key_manager: str = "CUSTOMER_MANAGED"  # CUSTOMER_MANAGED | PROVIDER_MANAGED
    key_spec: str = ""
    algorithm: str = ""
    key_size: int | None = None
    curve: str = ""
    key_state: str = ""
    key_usage: str = ""
    purpose: str = ""
    rotation_enabled: bool | None = None
    rotation_period_days: int | None = None
    multi_region: bool | None = None
    origin: str = ""
    aliases: list[str] = field(default_factory=list)
    grants: list[dict[str, Any]] = field(default_factory=list)
    hsm_backed: bool | None = None
    protection_level: str = ""
    expiration: str = ""
    created_at: str = ""
    dependencies: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    evidence: EvidenceSource = field(default_factory=EvidenceSource)

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "account": self.account,
            "region": self.region,
            "key_id": self.key_id,
            "name": self.name,
            "key_manager": self.key_manager,
            "key_spec": self.key_spec,
            "algorithm": self.algorithm,
            "key_size": self.key_size,
            "curve": self.curve,
            "key_state": self.key_state,
            "key_usage": self.key_usage,
            "purpose": self.purpose,
            "rotation_enabled": self.rotation_enabled,
            "rotation_period_days": self.rotation_period_days,
            "multi_region": self.multi_region,
            "origin": self.origin,
            "aliases": list(self.aliases),
            "grants": [dict(g) for g in self.grants],
            "hsm_backed": self.hsm_backed,
            "protection_level": self.protection_level,
            "expiration": self.expiration,
            "created_at": self.created_at,
            "dependencies": list(self.dependencies),
            "metadata": dict(self.metadata),
            "evidence": self.evidence.to_dict(),
        }


@dataclass
class CloudCertificate:
    """Certificate metadata + relationships (spec §4)."""

    provider: str
    account: str = ""
    region: str = ""
    certificate_id: str = ""
    domain: str = ""
    common_name: str = ""
    serial: str = ""
    issuer: str = ""
    ca_id: str = ""
    valid_from: str = ""
    valid_to: str = ""
    signature_algorithm: str = ""
    public_key_algorithm: str = ""
    key_size: int | None = None
    curve: str = ""
    status: str = ""
    imported: bool | None = None
    stored_in: str = ""
    used_by: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    evidence: EvidenceSource = field(default_factory=EvidenceSource)

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "account": self.account,
            "region": self.region,
            "certificate_id": self.certificate_id,
            "domain": self.domain,
            "common_name": self.common_name,
            "serial": self.serial,
            "issuer": self.issuer,
            "ca_id": self.ca_id,
            "valid_from": self.valid_from,
            "valid_to": self.valid_to,
            "signature_algorithm": self.signature_algorithm,
            "public_key_algorithm": self.public_key_algorithm,
            "key_size": self.key_size,
            "curve": self.curve,
            "status": self.status,
            "imported": self.imported,
            "stored_in": self.stored_in,
            "used_by": list(self.used_by),
            "dependencies": list(self.dependencies),
            "metadata": dict(self.metadata),
            "evidence": self.evidence.to_dict(),
        }


@dataclass
class CryptoObservation:
    """One normalized crypto observation feeding CBOM / posture / drift."""

    observation_id: str
    source_type: str
    resource: str
    provider: str
    account: str = ""
    region: str = ""
    kind: str = ""  # KEY | CERTIFICATE | ENCRYPTION | TLS | IPSEC | ...
    state: dict[str, Any] = field(default_factory=dict)
    evidence: EvidenceSource = field(default_factory=EvidenceSource)

    def to_dict(self) -> dict[str, Any]:
        return {
            "observation_id": self.observation_id,
            "source_type": self.source_type,
            "resource": self.resource,
            "provider": self.provider,
            "account": self.account,
            "region": self.region,
            "kind": self.kind,
            "state": dict(self.state),
            "evidence": self.evidence.to_dict(),
        }
