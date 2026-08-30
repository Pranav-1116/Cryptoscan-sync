"""ZELNX Cloud Discovery Engine — Cloud PQC Readiness Engine (spec §16).

For every cloud resource, produce a ``PQC_READINESS_SCORE`` and a verdict:

    PQC_READY | HYBRID_READY | MIGRATION_REQUIRED | BLOCKED | UNKNOWN

Readiness factors: current public-key algorithms, certificate algorithms,
cloud provider capability, service compatibility, application dependency,
library compatibility, HSM dependency, network dependency, vendor
readiness.

**Never classify something PQC-ready without supporting evidence** — the
engine starts from UNKNOWN and only upgrades when the injected evidence
satisfies the checklist.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from cloud_scanner.enterprise.certificate_discovery import CertificateInventory
from cloud_scanner.enterprise.key_discovery import KeyInventory
from cloud_scanner.enterprise.tls_discovery import TlsInventory

PQC_READY = "PQC_READY"
HYBRID_READY = "HYBRID_READY"
MIGRATION_REQUIRED = "MIGRATION_REQUIRED"
BLOCKED = "BLOCKED"
UNKNOWN = "UNKNOWN"

VERDICTS = (PQC_READY, HYBRID_READY, MIGRATION_REQUIRED, BLOCKED, UNKNOWN)

# public-key algorithms that must be replaced (or hybridized) for PQC
CLASSICAL_PUBLIC_KEY = ("RSA", "ECDSA", "ECDH", "DSA", "DH", "ED25519", "X25519", "EC")
PQC_PUBLIC_KEY = ("ML-KEM", "ML-DSA", "SLH-DSA", "KYBER", "DILITHIUM", "SPHINCS",
                  "X25519MLKEM768", "FALCON")

# cloud provider managed surfaces that already offer PQC-capable primitives
PROVIDER_PQC_CAPABILITY = {
    "aws": {"kms": "HYBRID_READY", "acm": "HYBRID_READY", "cloudfront": "UNKNOWN",
            "elbv2": "UNKNOWN", "eks": "HYBRID_READY"},
    "azure": {"key_vault": "HYBRID_READY", "managed_hsm": "HYBRID_READY",
              "front_door": "UNKNOWN", "aks": "HYBRID_READY"},
    "gcp": {"cloud_kms": "HYBRID_READY", "certificate_manager": "UNKNOWN",
            "load_balancer": "UNKNOWN", "gke": "HYBRID_READY"},
}


def _pick(row: dict[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if row.get(name) is not None:
            return row[name]
    return default


@dataclass
class PqcReadiness:
    """PQC readiness verdict + evidence for one cloud resource."""

    resource_id: str
    provider: str = ""
    account: str = ""
    resource_type: str = ""
    score: float = 0.0  # 0..10
    verdict: str = UNKNOWN
    public_key_algorithms: list[str] = field(default_factory=list)
    certificate_algorithms: list[str] = field(default_factory=list)
    provider_capability: str = "UNKNOWN"
    service_compatibility: str = "UNKNOWN"
    application_dependency: str = "UNKNOWN"
    library_compatibility: str = "UNKNOWN"
    hsm_dependency: str = "UNKNOWN"
    network_dependency: str = "UNKNOWN"
    vendor_readiness: str = "UNKNOWN"
    blockers: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "provider": self.provider,
            "account": self.account,
            "resource_type": self.resource_type,
            "pqc_readiness_score": round(self.score, 2),
            "verdict": self.verdict,
            "public_key_algorithms": list(self.public_key_algorithms),
            "certificate_algorithms": list(self.certificate_algorithms),
            "provider_capability": self.provider_capability,
            "service_compatibility": self.service_compatibility,
            "application_dependency": self.application_dependency,
            "library_compatibility": self.library_compatibility,
            "hsm_dependency": self.hsm_dependency,
            "network_dependency": self.network_dependency,
            "vendor_readiness": self.vendor_readiness,
            "blockers": list(self.blockers),
            "evidence": list(self.evidence),
        }


def is_classical(algorithm: str) -> bool:
    upper = str(algorithm or "").upper()
    return any(token in upper for token in CLASSICAL_PUBLIC_KEY)


def is_pqc(algorithm: str) -> bool:
    upper = str(algorithm or "").upper()
    return any(token in upper for token in PQC_PUBLIC_KEY)


@dataclass
class PqcInventory:
    """Readiness verdicts for every assessed resource."""

    results: list[PqcReadiness] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)

    def to_dicts(self) -> list[dict[str, Any]]:
        return [result.to_dict() for result in self.results]

    def by_verdict(self, verdict: str) -> list[PqcReadiness]:
        return [r for r in self.results if r.verdict == verdict]

    def summary(self) -> dict[str, Any]:
        return {
            "assessed": len(self.results),
            "by_verdict": {verdict: len(self.by_verdict(verdict)) for verdict in VERDICTS},
            "errors": self.errors,
        }


class CloudPqcReadinessEngine:
    """Assess readiness for keys, certificates and TLS endpoints.

    Extra evidence (``resource_evidence``) can be injected per resource id
    to satisfy the "no PQC-ready without evidence" rule: e.g.
    ``{"key-1": {"provider_capability": "HYBRID_READY", ...}}``.
    """

    def __init__(
        self,
        *,
        keys: KeyInventory | None = None,
        certificates: CertificateInventory | None = None,
        tls: TlsInventory | None = None,
        resource_evidence: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        self._keys = keys or KeyInventory()
        self._certificates = certificates or CertificateInventory()
        self._tls = tls or TlsInventory()
        self._evidence = dict(resource_evidence or {})

    # ------------------------------------------------------------------

    def assess(self) -> PqcInventory:
        inventory = PqcInventory()
        for key in self._keys.keys:
            inventory.results.append(self._assess(
                resource_id=key.key_id,
                provider=key.provider,
                account=key.account,
                resource_type=f"{key.provider}/key",
                algorithms=[key.algorithm] if key.algorithm else [],
                service=key.key_spec.split("_")[0].lower() if key.key_spec else "",
            ))
        for cert in self._certificates.certificates:
            inventory.results.append(self._assess(
                resource_id=cert.certificate_id,
                provider=cert.provider,
                account=cert.account,
                resource_type=f"{cert.provider}/certificate",
                algorithms=[cert.public_key_algorithm] if cert.public_key_algorithm else [],
                service="acm" if cert.provider == "aws" else (
                    "certificate_manager" if cert.provider == "gcp" else "key_vault"),
            ))
        for endpoint in self._tls.endpoints:
            inventory.results.append(self._assess(
                resource_id=endpoint.endpoint,
                provider=endpoint.provider,
                account=endpoint.account,
                resource_type=f"{endpoint.provider}/tls_endpoint",
                algorithms=[endpoint.key_exchange] if endpoint.key_exchange else [],
                service=endpoint.service,
            ))
        return inventory

    def _assess(self, *, resource_id: str, provider: str, account: str,
                resource_type: str, algorithms: list[str],
                service: str) -> PqcReadiness:
        evidence = self._evidence.get(resource_id, {})
        result = PqcReadiness(
            resource_id=resource_id,
            provider=provider,
            account=account,
            resource_type=resource_type,
            public_key_algorithms=[a for a in algorithms if a and a != "UNKNOWN"],
        )
        # factor: provider + service capability
        capability_table = PROVIDER_PQC_CAPABILITY.get(provider, {})
        result.provider_capability = str(
            evidence.get("provider_capability")
            or capability_table.get(service, "UNKNOWN")
            or "UNKNOWN"
        ).upper()
        for name, factor in (
            ("service_compatibility", "service_compatibility"),
            ("application_dependency", "application_dependency"),
            ("library_compatibility", "library_compatibility"),
            ("hsm_dependency", "hsm_dependency"),
            ("network_dependency", "network_dependency"),
            ("vendor_readiness", "vendor_readiness"),
        ):
            setattr(result, name, str(evidence.get(factor, "UNKNOWN")).upper())
        # certificates: signature algorithms feed certificate_algorithms
        cert_algos = [a for a in algorithms if a in ("RSA", "ECDSA", "ED25519", "EC")]
        result.certificate_algorithms = cert_algos
        if evidence.get("certificate_algorithms"):
            result.certificate_algorithms = [str(a) for a in evidence["certificate_algorithms"]]
        return self._score(result, evidence)

    def _score(self, result: PqcReadiness, evidence: dict[str, Any]) -> PqcReadiness:
        """Score 0..10 and derive the verdict with evidence requirements."""
        score = 0.0
        factors: list[tuple[str, str]] = [
            ("provider_capability", result.provider_capability),
            ("service_compatibility", result.service_compatibility),
            ("application_dependency", result.application_dependency),
            ("library_compatibility", result.library_compatibility),
            ("hsm_dependency", result.hsm_dependency),
            ("network_dependency", result.network_dependency),
            ("vendor_readiness", result.vendor_readiness),
        ]
        for name, value in factors:
            if value in ("PQC_READY", "SUPPORTED", "READY", "COMPATIBLE", "NONE", "NO_DEPENDENCY"):
                score += 1.25
                result.evidence.append(f"{name}={value}")
            elif value in ("HYBRID_READY", "HYBRID"):
                score += 0.75
                result.evidence.append(f"{name}={value}")
            elif value in ("BLOCKED", "UNSUPPORTED", "INCOMPATIBLE", "REQUIRED"):
                result.blockers.append(f"{name}={value}")
        # public key algorithms weigh on the score
        classical = [a for a in result.public_key_algorithms if is_classical(a)]
        pqc = [a for a in result.public_key_algorithms if is_pqc(a)]
        if pqc:
            score += 1.0
            result.evidence.append(f"pqc_algorithm={','.join(pqc)}")
        if classical:
            score = max(0.0, score - 0.5 * len(classical))
            result.evidence.append(f"classical_algorithm={','.join(classical)}")
        if evidence.get("pqc_algorithm"):
            score += 1.0
            result.evidence.append(f"pqc_algorithm={evidence['pqc_algorithm']}")
        if evidence.get("hybrid_capable") is True:
            score += 1.0
            result.evidence.append("hybrid_capable=true")
        score = min(10.0, max(0.0, score))
        result.score = round(score, 2)
        # verdict — conservative, evidence-gated
        if result.blockers:
            result.verdict = BLOCKED
        elif score >= 9.0 and result.evidence and self._has_ready_evidence(result):
            result.verdict = PQC_READY
        elif score >= 6.0 and result.evidence:
            result.verdict = HYBRID_READY
        elif score >= 3.0:
            result.verdict = MIGRATION_REQUIRED
        else:
            result.verdict = UNKNOWN if not result.evidence else MIGRATION_REQUIRED
        return result

    @staticmethod
    def _has_ready_evidence(result: PqcReadiness) -> bool:
        """PQC_READY requires positive evidence on capability, service,
        application, library and network factors (never inferred)."""
        required = ("provider_capability", "service_compatibility",
                    "application_dependency", "library_compatibility",
                    "network_dependency")
        for factor in required:
            if getattr(result, factor) in ("UNKNOWN", ""):
                return False
        return True
