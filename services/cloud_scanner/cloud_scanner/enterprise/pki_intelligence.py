"""ZELNX Cloud Discovery Engine — Cloud PKI Intelligence Engine (spec §5).

Discovers the private CA estate and trust relationships that matter for PQC
migration:

- root CA relationships, intermediate CAs, private CAs, issuing CAs
- certificate templates where available
- certificate dependencies + consumers
- trust relationships
- certificate expiration, signature algorithms, public-key algorithms

A CA hierarchy is a tree: root CAs at the top, issuing CAs below, signed
certificates as leaves.  Weak signature algorithms anywhere in the chain are
flagged — a PQC migration must replace the whole chain, not just the leaf.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from cloud_scanner.enterprise.models import CloudCertificate, EvidenceSource

CaEnumerator = Callable[[], list[dict[str, Any]]]

WEAK_SIGNATURE_ALGORITHMS = ("MD5", "SHA1", "SHA-1", "MD2", "SHA224")
WEAK_PUBLIC_KEY_ALGORITHMS = ("RSA",)  # RSA alone is not weak; size decides
WEAK_RSA_SIZES = {512, 1024}


@dataclass
class CaNode:
    """One CA in the hierarchy."""

    ca_id: str
    name: str = ""
    provider: str = ""
    account: str = ""
    ca_type: str = ""  # ROOT | SUBORDINATE | INTERMEDIATE | ISSUING | UNKNOWN
    parent_id: str = ""
    status: str = ""
    templates: list[str] = field(default_factory=list)
    signature_algorithm: str = ""
    public_key_algorithm: str = ""
    key_size: int | None = None
    curve: str = ""
    expires_at: str = ""
    consumers: list[str] = field(default_factory=list)
    evidence: EvidenceSource = field(default_factory=EvidenceSource)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ca_id": self.ca_id,
            "name": self.name,
            "provider": self.provider,
            "account": self.account,
            "ca_type": self.ca_type,
            "parent_id": self.parent_id,
            "status": self.status,
            "templates": list(self.templates),
            "signature_algorithm": self.signature_algorithm,
            "public_key_algorithm": self.public_key_algorithm,
            "key_size": self.key_size,
            "curve": self.curve,
            "expires_at": self.expires_at,
            "consumers": list(self.consumers),
            "evidence": self.evidence.to_dict(),
        }


@dataclass
class TrustRelationship:
    """A signed trust edge (parent CA signs child CA or certificate)."""

    parent_id: str
    child_id: str
    kind: str = "SIGNS"  # SIGNS | CROSS_SIGN | ROOT_TRUST
    provider: str = ""
    account: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "parent_id": self.parent_id,
            "child_id": self.child_id,
            "kind": self.kind,
            "provider": self.provider,
            "account": self.account,
        }


@dataclass
class PkiIntelligence:
    """CA hierarchy + trust graph + chain health."""

    cas: list[CaNode] = field(default_factory=list)
    trust: list[TrustRelationship] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)

    def to_dicts(self) -> list[dict[str, Any]]:
        return [ca.to_dict() for ca in self.cas]

    def roots(self) -> list[CaNode]:
        ids = {ca.ca_id for ca in self.cas}
        return [ca for ca in self.cas if not ca.parent_id or ca.parent_id not in ids]

    def chain_for(self, ca_id: str) -> list[CaNode]:
        """Root -> ... -> this CA (closest to the leaf last)."""
        by_id = {ca.ca_id: ca for ca in self.cas}
        chain: list[CaNode] = []
        seen: set[str] = set()
        node = by_id.get(ca_id)
        while node is not None and node.ca_id not in seen:
            chain.append(node)
            seen.add(node.ca_id)
            node = by_id.get(node.parent_id) if node.parent_id else None
        return list(reversed(chain))

    def weak_chains(self) -> list[dict[str, Any]]:
        """Chains containing weak signature algorithms or small RSA keys."""
        flagged: list[dict[str, Any]] = []
        for ca in self.cas:
            chain = self.chain_for(ca.ca_id)
            issues: list[str] = []
            for node in chain:
                sig = str(node.signature_algorithm or "").upper()
                if any(weak in sig for weak in ("MD5", "SHA1", "SHA-1", "MD2", "SHA224")):
                    issues.append(f"{node.ca_id}: weak signature {node.signature_algorithm}")
                if str(node.public_key_algorithm or "").upper() == "RSA" and node.key_size in WEAK_RSA_SIZES:
                    issues.append(f"{node.ca_id}: small RSA key {node.key_size}")
            if issues:
                flagged.append({"ca_id": ca.ca_id, "chain": [n.ca_id for n in chain],
                                "issues": issues})
        return flagged

    def expiring_cas(self, *, days: int = 90, now: Any | None = None) -> list[CaNode]:
        from datetime import datetime, timedelta, timezone

        from cloud_scanner.enterprise.models import parse_iso
        from shared_models.chrono import aware

        now = aware(now) or datetime.now(timezone.utc)
        horizon = now + timedelta(days=max(0, int(days)))
        result: list[CaNode] = []
        for ca in self.cas:
            if not ca.expires_at:
                continue
            expires = parse_iso(ca.expires_at)
            if expires is None:
                continue
            expires = aware(expires)
            if expires <= horizon:
                result.append(ca)
        return result

    def summary(self) -> dict[str, Any]:
        return {
            "cas": len(self.cas),
            "roots": len(self.roots()),
            "trust_relationships": len(self.trust),
            "weak_chains": len(self.weak_chains()),
            "errors": self.errors,
        }


class PkiIntelligenceEngine:
    """Build the PKI hierarchy from injected CA enumerators.

    Adapter shape: ``{"provider": "aws", "enumerate_cas": fn,
    "enumerate_trust": fn | None}``.
    """

    def __init__(self, providers: list[dict[str, Any]]) -> None:
        self._providers = list(providers)

    def discover(self, *, certificates: list[CloudCertificate] | None = None) -> PkiIntelligence:
        pki = PkiIntelligence()
        for entry in self._providers:
            provider = str(entry.get("provider") or "").lower()
            enumerator = entry.get("enumerate_cas")
            if enumerator is None:
                continue
            try:
                rows = enumerator() or []
            except Exception as exc:  # noqa: BLE001
                pki.errors.append(
                    {"provider": provider, "kind": "enumerate", "detail": str(exc)[:300]}
                )
                continue
            for row in rows:
                if not isinstance(row, dict):
                    continue
                pki.cas.append(self._ca(row, provider=provider))
                parent = str(row.get("parent_id") or "")
                if parent:
                    pki.trust.append(TrustRelationship(
                        parent_id=parent,
                        child_id=str(row.get("ca_id") or row.get("id") or ""),
                        kind="SIGNS",
                        provider=provider,
                        account=str(row.get("account") or ""),
                    ))
            for rel in (entry.get("enumerate_trust") or (lambda: []))() or []:
                if isinstance(rel, dict):
                    pki.trust.append(TrustRelationship(
                        parent_id=str(rel.get("parent_id") or ""),
                        child_id=str(rel.get("child_id") or ""),
                        kind=str(rel.get("kind") or "SIGNS"),
                        provider=provider,
                        account=str(rel.get("account") or ""),
                    ))
        # attach certificate consumers to their issuing CA
        for cert in certificates or []:
            for ca in pki.cas:
                if cert.ca_id and cert.ca_id == ca.ca_id:
                    if cert.domain not in ca.consumers:
                        ca.consumers.append(cert.domain)
        return pki

    @staticmethod
    def _ca(row: dict[str, Any], *, provider: str) -> CaNode:
        sig = str(row.get("signature_algorithm") or row.get("signatureAlgorithm") or "")
        pub = str(row.get("public_key_algorithm") or row.get("key_algorithm") or "")
        return CaNode(
            ca_id=str(row.get("ca_id") or row.get("id") or row.get("arn") or ""),
            name=str(row.get("name") or row.get("display_name") or ""),
            provider=provider,
            account=str(row.get("account") or ""),
            ca_type=str(row.get("ca_type") or row.get("type") or "UNKNOWN").upper(),
            parent_id=str(row.get("parent_id") or ""),
            status=str(row.get("status") or ""),
            templates=[str(t) for t in (row.get("templates") or [])],
            signature_algorithm=sig,
            public_key_algorithm=pub,
            key_size=row.get("key_size") or row.get("keySize"),
            curve=str(row.get("curve") or ""),
            expires_at=str(row.get("expires_at") or row.get("valid_to") or ""),
            consumers=[str(c) for c in (row.get("consumers") or [])],
            evidence=EvidenceSource(
                source_provider=provider,
                account=str(row.get("account") or ""),
                api_source=str(row.get("api_source") or "pki-intelligence"),
            ),
        )
