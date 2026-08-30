"""ZELNX Cloud Discovery Engine — multi-cloud relationship discovery
(spec §14).

Identifies cryptographic dependencies *across* clouds:

    AWS Application ──▶ Azure API ──▶ GCP Service

Supported relationship classes: cross-cloud TLS, VPN / private
connectivity, API relationships, certificate dependencies, DNS
relationships and identity federation.  Each relationship is typed and can
be resolved onto the unified dependency graph.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from cloud_scanner.enterprise.models import EvidenceSource

RelationshipEnumerator = Callable[[], list[dict[str, Any]]]

CROSS_CLOUD_KINDS = ("CROSS_CLOUD_TLS", "CROSS_CLOUD_VPN", "PRIVATE_CONNECTIVITY",
                     "API_RELATIONSHIP", "CERTIFICATE_DEPENDENCY", "DNS_RELATIONSHIP",
                     "IDENTITY_FEDERATION")


def _pick(row: dict[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if row.get(name) is not None:
            return row[name]
    return default


@dataclass
class CrossCloudRelationship:
    """One cross-cloud edge."""

    source: str
    target: str
    kind: str = "API_RELATIONSHIP"
    source_provider: str = ""
    target_provider: str = ""
    source_account: str = ""
    target_account: str = ""
    crypto_dependencies: list[str] = field(default_factory=list)
    evidence: EvidenceSource = field(default_factory=EvidenceSource)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "kind": self.kind,
            "source_provider": self.source_provider,
            "target_provider": self.target_provider,
            "source_account": self.source_account,
            "target_account": self.target_account,
            "crypto_dependencies": list(self.crypto_dependencies),
            "evidence": self.evidence.to_dict(),
        }


@dataclass
class MultiCloudInventory:
    """All cross-cloud relationships."""

    relationships: list[CrossCloudRelationship] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)

    def to_dicts(self) -> list[dict[str, Any]]:
        return [rel.to_dict() for rel in self.relationships]

    def by_kind(self, kind: str) -> list[CrossCloudRelationship]:
        return [rel for rel in self.relationships if rel.kind == kind]

    def count(self) -> int:
        return len(self.relationships)

    def summary(self) -> dict[str, Any]:
        return {
            "relationships": len(self.relationships),
            "by_kind": {
                kind: len(self.by_kind(kind)) for kind in CROSS_CLOUD_KINDS
            },
            "errors": self.errors,
        }


class MultiCloudDiscovery:
    """Discover cross-cloud relationships from injected enumerators."""

    def __init__(self, providers: list[dict[str, Any]]) -> None:
        self._providers = list(providers)

    def discover(self) -> MultiCloudInventory:
        inventory = MultiCloudInventory()
        for entry in self._providers:
            provider = str(entry.get("provider") or "").lower()
            enumerator = entry.get("enumerate_cross_cloud")
            if enumerator is None:
                continue
            try:
                rows = enumerator() or []
            except Exception as exc:  # noqa: BLE001
                inventory.errors.append(
                    {"provider": provider, "kind": "enumerate", "detail": str(exc)[:300]}
                )
                continue
            for row in rows:
                if isinstance(row, dict):
                    inventory.relationships.append(self._relationship(row, provider=provider))
        return inventory

    @staticmethod
    def _relationship(row: dict[str, Any], *, provider: str) -> CrossCloudRelationship:
        source_provider = str(_pick(row, "source_provider", default=provider) or provider)
        target_provider = str(_pick(row, "target_provider", default="") or "")
        return CrossCloudRelationship(
            source=str(_pick(row, "source", "application", "workload", default="") or ""),
            target=str(_pick(row, "target", "service", "api", default="") or ""),
            kind=str(_pick(row, "kind", "relationship", "type", default="API_RELATIONSHIP") or ""),
            source_provider=source_provider,
            target_provider=target_provider,
            source_account=str(_pick(row, "source_account", default="") or ""),
            target_account=str(_pick(row, "target_account", default="") or ""),
            crypto_dependencies=[str(d) for d in (_pick(row, "crypto_dependencies", "crypto",
                                                        default=[]) or [])],
            evidence=EvidenceSource(
                source_provider=provider,
                account=str(_pick(row, "account", default="") or ""),
                api_source=str(_pick(row, "api_source", default="multi-cloud") or ""),
            ),
        )
