"""ZELNX Cloud Discovery Engine — certificate discovery (spec §4).

Discovers certificate metadata across all three clouds and builds a unified
certificate graph:

    Cloud Certificate
         ├── Used By Load Balancer
         ├── Used By Application
         ├── Issued By CA
         ├── Stored In Vault
         └── Connected To Domain

- AWS:    ACM certificates, imported metadata, load balancer / API Gateway /
          CloudFront certificates, private CA relationships
- Azure:  Key Vault certificate metadata, Application Gateway / Front Door /
          App Service certificates, private certificate infrastructure refs
- GCP:    Certificate Manager, load balancer certificates, CA Service
          relationships, workload certificate references

Private key material is never collected — metadata and references only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from cloud_scanner.enterprise.models import CloudCertificate, EvidenceSource

CertificateEnumerator = Callable[[], list[dict[str, Any]]]

RELATION_KINDS = ("USED_BY_LOAD_BALANCER", "USED_BY_APPLICATION", "ISSUED_BY_CA",
                  "STORED_IN_VAULT", "CONNECTED_TO_DOMAIN")


def normalize_certificate(row: dict[str, Any], *, provider: str, account: str = "",
                          region: str = "", evidence: EvidenceSource | None = None) -> CloudCertificate:
    """Normalize one raw provider certificate row into the shared model."""
    pub = str(_pick(row, "public_key_algorithm", "key_algorithm", "publicKeyAlgorithm",
                    default="") or "")
    bits = _pick(row, "key_size", "public_key_size", "keySize", "publicKeySize", default=None)
    cert = CloudCertificate(
        provider=provider,
        account=str(_pick(row, "account", "subscription", "project", default=account) or account),
        region=str(_pick(row, "region", default=region) or region),
        certificate_id=str(_pick(row, "certificate_id", "id", "arn", "resourceId",
                                 "name", default="") or ""),
        domain=str(_pick(row, "domain", "dns_name", "hostname", "domains", default="") or ""),
        common_name=str(_pick(row, "common_name", "commonName", default="") or ""),
        serial=str(_pick(row, "serial", "serial_number", default="") or ""),
        issuer=str(_pick(row, "issuer", "issuer_name", default="") or ""),
        ca_id=str(_pick(row, "ca_id", "issuer_arn", "issuerId", default="") or ""),
        valid_from=str(_pick(row, "valid_from", "not_before", "validFrom", "created_at",
                             default="") or ""),
        valid_to=str(_pick(row, "valid_to", "not_after", "validTo", "expiry",
                           "expiration", default="") or ""),
        signature_algorithm=str(_pick(row, "signature_algorithm", "signatureAlgorithm",
                                      default="") or ""),
        public_key_algorithm=pub,
        key_size=int(bits) if isinstance(bits, (int, float)) and not isinstance(bits, bool) else bits,
        curve=str(_pick(row, "curve", default="") or ""),
        status=str(_pick(row, "status", "certificate_status", default="") or ""),
        imported=_pick(row, "imported", "is_imported", "type", default=None),
        stored_in=str(_pick(row, "stored_in", "vault", "key_vault", "secret_name",
                            default="") or ""),
        used_by=[str(item) for item in (_pick(row, "used_by", "usages", default=[]) or [])],
        dependencies=[str(item) for item in (_pick(row, "dependencies", default=[]) or [])],
        metadata=dict(_pick(row, "metadata", default={}) or {}),
        evidence=evidence or EvidenceSource(source_provider=provider, account=account),
    )
    if cert.imported is True or str(_pick(row, "imported", default="")).upper() == "IMPORTED":
        cert.imported = True
    return cert


def _pick(row: dict[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if row.get(name) is not None:
            return row[name]
    return default


@dataclass
class CertificateRelation:
    """One edge in the unified certificate graph."""

    certificate_id: str
    kind: str
    target: str
    provider: str = ""
    account: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "certificate_id": self.certificate_id,
            "kind": self.kind,
            "target": self.target,
            "provider": self.provider,
            "account": self.account,
        }


@dataclass
class CertificateInventory:
    """All discovered certificates + the unified certificate graph."""

    certificates: list[CloudCertificate] = field(default_factory=list)
    relations: list[CertificateRelation] = field(default_factory=list)
    truncated: bool = False
    errors: list[dict[str, Any]] = field(default_factory=list)

    def to_dicts(self) -> list[dict[str, Any]]:
        return [cert.to_dict() for cert in self.certificates]

    def by_provider(self, provider: str) -> list[CloudCertificate]:
        return [cert for cert in self.certificates if cert.provider == provider]

    def count(self, provider: str | None = None) -> int:
        return len(self.by_provider(provider)) if provider else len(self.certificates)

    def expiring(self, *, days: int = 30, now: Any | None = None) -> list[CloudCertificate]:
        """Certificates expiring within ``days`` (or already expired)."""
        from datetime import datetime, timedelta, timezone

        from cloud_scanner.enterprise.models import parse_iso
        from shared_models.chrono import aware

        now = aware(now) or datetime.now(timezone.utc)
        result: list[CloudCertificate] = []
        for cert in self.certificates:
            if not cert.valid_to:
                continue
            valid_to = parse_iso(cert.valid_to)
            if valid_to is None:
                continue
            valid_to = aware(valid_to)
            if valid_to <= now + timedelta(days=max(0, int(days))):
                result.append(cert)
        return result

    def summary(self) -> dict[str, Any]:
        return {
            "certificates": len(self.certificates),
            "by_provider": {
                provider: len(self.by_provider(provider))
                for provider in ("aws", "azure", "gcp")
            },
            "relations": len(self.relations),
            "by_relation_kind": {
                kind: sum(1 for rel in self.relations if rel.kind == kind)
                for kind in RELATION_KINDS
            },
            "truncated": self.truncated,
            "errors": self.errors,
        }


class CertificateDiscovery:
    """Discover certificates + build the unified graph from adapters.

    Adapter shape: ``{"provider": "aws", "enumerate_certificates": fn,
    "enumerate_relations": fn | None}``.  Relations may also be embedded in
    certificate rows as ``used_by`` / ``dependencies``.
    """

    def __init__(self, providers: list[dict[str, Any]], *, max_certificates: int = 2000) -> None:
        self._providers = list(providers)
        self._max_certificates = max_certificates

    def discover(self) -> CertificateInventory:
        inventory = CertificateInventory()
        for entry in self._providers:
            provider = str(entry.get("provider") or "").lower()
            enumerator = entry.get("enumerate_certificates")
            if enumerator is None:
                inventory.errors.append(
                    {"provider": provider, "kind": "no_enumerator",
                     "detail": "no enumerate_certificates callable injected"}
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
                if len(inventory.certificates) >= self._max_certificates:
                    inventory.truncated = True
                    break
                if not isinstance(row, dict):
                    continue
                cert = normalize_certificate(row, provider=provider)
                inventory.certificates.append(cert)
                self._relations_from_row(inventory, cert, row)
            relation_fn = entry.get("enumerate_relations")
            if relation_fn is not None:
                try:
                    for rel in relation_fn() or []:
                        if isinstance(rel, dict):
                            inventory.relations.append(CertificateRelation(
                                certificate_id=str(rel.get("certificate_id") or ""),
                                kind=str(rel.get("kind") or ""),
                                target=str(rel.get("target") or ""),
                                provider=provider,
                                account=str(rel.get("account") or ""),
                            ))
                except Exception as exc:  # noqa: BLE001
                    inventory.errors.append(
                        {"provider": provider, "kind": "relations", "detail": str(exc)[:300]}
                    )
        return inventory

    @staticmethod
    def _relations_from_row(inventory: CertificateInventory, cert: CloudCertificate,
                            row: dict[str, Any]) -> None:
        for usage in cert.used_by:
            inventory.relations.append(CertificateRelation(
                certificate_id=cert.certificate_id,
                kind="USED_BY_APPLICATION",
                target=usage,
                provider=cert.provider,
                account=cert.account,
            ))
        if cert.ca_id:
            inventory.relations.append(CertificateRelation(
                certificate_id=cert.certificate_id,
                kind="ISSUED_BY_CA",
                target=cert.ca_id,
                provider=cert.provider,
                account=cert.account,
            ))
        if cert.stored_in:
            inventory.relations.append(CertificateRelation(
                certificate_id=cert.certificate_id,
                kind="STORED_IN_VAULT",
                target=cert.stored_in,
                provider=cert.provider,
                account=cert.account,
            ))
        if cert.domain:
            inventory.relations.append(CertificateRelation(
                certificate_id=cert.certificate_id,
                kind="CONNECTED_TO_DOMAIN",
                target=cert.domain,
                provider=cert.provider,
                account=cert.account,
            ))
        for dep in cert.dependencies:
            inventory.relations.append(CertificateRelation(
                certificate_id=cert.certificate_id,
                kind="USED_BY_LOAD_BALANCER",
                target=dep,
                provider=cert.provider,
                account=cert.account,
            ))
