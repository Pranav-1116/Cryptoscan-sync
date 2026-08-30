"""ZELNX Cloud Discovery Engine — cloud encryption discovery (spec §6).

For every storage / database resource, capture:

    Encryption at Rest | Encryption in Transit | Customer Managed Key |
    Provider Managed Key | Key Reference | Certificate Reference |
    Cryptographic Algorithm | Rotation Status | Encryption State

Storage:  S3, Azure Blob, GCS
Databases: RDS, Aurora, Azure SQL + database services, Cloud SQL, Spanner

State is one of: ENCRYPTED_CMK / ENCRYPTED_PMK / ENCRYPTED_UNKNOWN_KEY /
NOT_ENCRYPTED / UNKNOWN.  Never collects key material — only references.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from cloud_scanner.enterprise.models import EvidenceSource

ResourceEnumerator = Callable[[], list[dict[str, Any]]]


def _pick(row: dict[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if row.get(name) is not None:
            return row[name]
    return default


@dataclass
class EncryptionState:
    """Encryption posture of one storage / database resource."""

    resource_id: str
    provider: str
    account: str = ""
    region: str = ""
    resource_type: str = ""  # s3 | blob | gcs | rds | aurora | sql | cloud_sql | spanner | ...
    at_rest: str = "UNKNOWN"  # ENCRYPTED_CMK | ENCRYPTED_PMK | ENCRYPTED_UNKNOWN_KEY | NOT_ENCRYPTED | UNKNOWN
    in_transit: str = "UNKNOWN"  # TLS_ENABLED | TLS_DISABLED | UNKNOWN
    encryption_algorithm: str = ""
    key_reference: str = ""  # KMS ARN / key vault URI / CMEK name (never material)
    certificate_reference: str = ""
    rotation_status: str = "UNKNOWN"
    customer_managed: bool | None = None
    evidence: EvidenceSource = field(default_factory=EvidenceSource)

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "provider": self.provider,
            "account": self.account,
            "region": self.region,
            "resource_type": self.resource_type,
            "at_rest": self.at_rest,
            "in_transit": self.in_transit,
            "encryption_algorithm": self.encryption_algorithm,
            "key_reference": self.key_reference,
            "certificate_reference": self.certificate_reference,
            "rotation_status": self.rotation_status,
            "customer_managed": self.customer_managed,
            "evidence": self.evidence.to_dict(),
        }


@dataclass
class EncryptionInventory:
    """All storage/database encryption states."""

    resources: list[EncryptionState] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)

    def to_dicts(self) -> list[dict[str, Any]]:
        return [resource.to_dict() for resource in self.resources]

    def count(self, provider: str | None = None) -> int:
        if provider is None:
            return len(self.resources)
        return sum(1 for r in self.resources if r.provider == provider)

    def unencrypted(self) -> list[EncryptionState]:
        return [r for r in self.resources
                if r.at_rest in ("NOT_ENCRYPTED",) or r.in_transit == "TLS_DISABLED"]

    def customer_managed(self) -> list[EncryptionState]:
        return [r for r in self.resources if r.at_rest == "ENCRYPTED_CMK"]

    def summary(self) -> dict[str, Any]:
        return {
            "resources": len(self.resources),
            "by_provider": {
                provider: self.count(provider) for provider in ("aws", "azure", "gcp")
            },
            "unencrypted_or_no_tls": len(self.unencrypted()),
            "customer_managed": len(self.customer_managed()),
            "errors": self.errors,
        }


def at_rest_state(encrypted: bool | None, key_ref: str | None,
                  customer_managed: bool | None = None) -> str:
    """Derive the at-rest state from encryption flags + key reference."""
    if encrypted is False:
        return "NOT_ENCRYPTED"
    if encrypted is not True:
        return "UNKNOWN"
    if key_ref:
        if customer_managed is False:
            return "ENCRYPTED_PMK"
        if customer_managed is True:
            return "ENCRYPTED_CMK"
        return "ENCRYPTED_UNKNOWN_KEY"
    if customer_managed is True:
        return "ENCRYPTED_CMK"
    if customer_managed is False:
        return "ENCRYPTED_PMK"
    return "ENCRYPTED_UNKNOWN_KEY"


def normalize_encryption(row: dict[str, Any], *, provider: str) -> EncryptionState:
    key_ref = str(_pick(row, "key_reference", "kms_key_id", "kmsKeyId", "encryption_key",
                        "key_id", "cmek", "key_vault", "keyvault_uri", default="") or "")
    cmk = _pick(row, "customer_managed", "customer_managed_key", "cmk", default=None)
    encrypted = _pick(row, "encrypted", "encryption_enabled", "encryptionEnabled", default=None)
    return EncryptionState(
        resource_id=str(_pick(row, "resource_id", "id", "name", "bucket", "database",
                              "instance", default="") or ""),
        provider=provider,
        account=str(_pick(row, "account", "subscription", "project", default="") or ""),
        region=str(_pick(row, "region", default="") or ""),
        resource_type=str(_pick(row, "resource_type", "type", default="") or ""),
        at_rest=at_rest_state(encrypted, key_ref, cmk),
        in_transit=str(_pick(row, "in_transit", "tls", "ssl_enabled", "transit_encryption",
                             default="UNKNOWN") or "UNKNOWN"),
        encryption_algorithm=str(_pick(row, "encryption_algorithm", "algorithm", "sse_algorithm",
                                       default="") or ""),
        key_reference=key_ref,
        certificate_reference=str(_pick(row, "certificate_reference", "ca_certificate",
                                        "tls_certificate", default="") or ""),
        rotation_status=str(_pick(row, "rotation_status", "key_rotation", default="UNKNOWN") or "UNKNOWN"),
        customer_managed=cmk,
        evidence=EvidenceSource(
            source_provider=provider,
            account=str(_pick(row, "account", "subscription", "project", default="") or ""),
            api_source=str(_pick(row, "api_source", default="cloud-encryption-discovery") or ""),
            confidence=str(_pick(row, "confidence", default="MEDIUM") or "MEDIUM"),
        ),
    )


class EncryptionDiscovery:
    """Run encryption discovery for injected storage/database enumerators.

    Adapter shape: ``{"provider": "aws", "enumerate_encryption": fn}``.
    """

    def __init__(self, providers: list[dict[str, Any]], *, max_resources: int = 2000) -> None:
        self._providers = list(providers)
        self._max_resources = max_resources

    def discover(self) -> EncryptionInventory:
        inventory = EncryptionInventory()
        for entry in self._providers:
            provider = str(entry.get("provider") or "").lower()
            enumerator = entry.get("enumerate_encryption")
            if enumerator is None:
                inventory.errors.append(
                    {"provider": provider, "kind": "no_enumerator",
                     "detail": "no enumerate_encryption callable injected"}
                )
                continue
            try:
                rows = enumerator() or []
            except Exception as exc:  # noqa: BLE001
                inventory.errors.append(
                    {"provider": provider, "kind": "enumerate", "detail": str(exc)[:300]}
                )
                continue
            for row in rows:
                if len(inventory.resources) >= self._max_resources:
                    break
                if isinstance(row, dict):
                    inventory.resources.append(normalize_encryption(row, provider=provider))
        return inventory
