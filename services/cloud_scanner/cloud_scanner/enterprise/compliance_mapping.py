"""ZELNX Cloud Discovery Engine — cloud compliance mapping (spec §19).

A framework (not a hard-coded sector) that maps cloud crypto configuration
to controls:

    Cloud Resource ── Crypto Configuration ── Policy Evaluation
        ── Control Mapping ── Evidence ── Compliance Status

Policies are declarative rules evaluated against observations; every rule
maps to one or more controls; every control carries evidence references and
a status.  New sectors plug in by registering policy sets (e.g. PCI-DSS,
NIST SP 800-57, EU banking EBA, regional GDPR-derived crypto controls).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from cloud_scanner.enterprise.certificate_discovery import CertificateInventory
from cloud_scanner.enterprise.key_discovery import KeyInventory
from cloud_scanner.enterprise.tls_discovery import TLS_LEGACY, TLS_WEAK, TlsInventory

COMPLIANT = "COMPLIANT"
NON_COMPLIANT = "NON_COMPLIANT"
NOT_APPLICABLE = "NOT_APPLICABLE"
UNKNOWN = "UNKNOWN"

STATUSES = (COMPLIANT, NON_COMPLIANT, NOT_APPLICABLE, UNKNOWN)


@dataclass
class ComplianceRule:
    """One declarative crypto policy rule."""

    rule_id: str
    description: str
    controls: list[str]
    sector: str = "GENERIC"
    severity: str = "MEDIUM"
    evaluate: Callable[[dict[str, Any]], str] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "description": self.description,
            "controls": list(self.controls),
            "sector": self.sector,
            "severity": self.severity,
        }


@dataclass
class ComplianceResult:
    """Outcome of evaluating a rule against a resource."""

    resource_id: str
    rule_id: str
    status: str = UNKNOWN
    evidence_refs: list[str] = field(default_factory=list)
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "rule_id": self.rule_id,
            "status": self.status,
            "evidence_refs": list(self.evidence_refs),
            "detail": self.detail,
        }


@dataclass
class ComplianceReport:
    """Rule -> control -> status rollup."""

    results: list[ComplianceResult] = field(default_factory=list)
    sectors: list[str] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)
    _rules_by_id: dict[str, list[str]] = field(default_factory=dict, repr=False)

    def to_dicts(self) -> list[dict[str, Any]]:
        return [result.to_dict() for result in self.results]

    def by_status(self, status: str) -> list[ComplianceResult]:
        return [r for r in self.results if r.status == status]

    def controls(self) -> dict[str, str]:
        """Control -> worst status across resources."""
        by_control: dict[str, list[str]] = {}
        rule_by_id = self._rules_by_id
        for result in self.results:
            controls = rule_by_id.get(result.rule_id, [])
            for control in controls:
                by_control.setdefault(control, []).append(result.status)
        rank = {UNKNOWN: 0, COMPLIANT: 1, NOT_APPLICABLE: 2, NON_COMPLIANT: 3}
        return {
            control: max(statuses, key=lambda s: rank.get(s, 0))
            for control, statuses in by_control.items()
        }

    def summary(self) -> dict[str, Any]:
        return {
            "evaluations": len(self.results),
            "by_status": {
                status: len(self.by_status(status)) for status in STATUSES
            },
            "sectors": list(self.sectors),
            "controls": self.controls(),
            "errors": self.errors,
        }


class ComplianceMappingEngine:
    """Evaluate declarative rules against the discovery inventories."""

    def __init__(
        self,
        *,
        keys: KeyInventory | None = None,
        certificates: CertificateInventory | None = None,
        tls: TlsInventory | None = None,
        rules: list[ComplianceRule] | None = None,
    ) -> None:
        self._keys = keys or KeyInventory()
        self._certificates = certificates or CertificateInventory()
        self._tls = tls or TlsInventory()
        self._rules = list(rules or default_rules())

    def evaluate(self, *, sectors: list[str] | None = None) -> ComplianceReport:
        return self.evaluate_observations(self._observations(), sectors=sectors)

    def evaluate_observations(self, observations: dict[str, dict[str, Any]],
                              *, sectors: list[str] | None = None) -> ComplianceReport:
        """Evaluate rules against a raw observations map (also used by the
        event monitor over live CBOM state)."""
        report = ComplianceReport()
        report.sectors = list({rule.sector for rule in self._rules})
        wanted = {str(s).upper() for s in (sectors or [])}
        report._rules_by_id = {rule.rule_id: rule.controls for rule in self._rules}
        for rule in self._rules:
            if wanted and rule.sector not in wanted:
                continue
            for resource_id, config in observations.items():
                status = UNKNOWN
                detail = ""
                if rule.evaluate is not None:
                    try:
                        status = rule.evaluate(config)
                    except Exception as exc:  # noqa: BLE001
                        status = UNKNOWN
                        detail = str(exc)[:200]
                else:
                    status, detail = _default_evaluate(rule.rule_id, config)
                report.results.append(ComplianceResult(
                    resource_id=resource_id,
                    rule_id=rule.rule_id,
                    status=status,
                    evidence_refs=[f"evidence://{resource_id}"],
                    detail=detail,
                ))
        return report

    # ------------------------------------------------------------------

    def _observations(self) -> dict[str, dict[str, Any]]:
        observations: dict[str, dict[str, Any]] = {}
        for key in self._keys.keys:
            observations[key.key_id] = {
                "kind": "key",
                "provider": key.provider,
                "algorithm": key.algorithm,
                "key_size": key.key_size,
                "rotation_enabled": key.rotation_enabled,
                "hsm_backed": key.hsm_backed,
            }
        for cert in self._certificates.certificates:
            observations[cert.certificate_id] = {
                "kind": "certificate",
                "provider": cert.provider,
                "signature_algorithm": cert.signature_algorithm,
                "public_key_algorithm": cert.public_key_algorithm,
                "key_size": cert.key_size,
                "valid_to": cert.valid_to,
            }
        for endpoint in self._tls.endpoints:
            observations[endpoint.endpoint] = {
                "kind": "tls",
                "provider": endpoint.provider,
                "classification": endpoint.classification,
                "tls_version": endpoint.tls_version,
            }
        return observations


def _default_evaluate(rule_id: str, config: dict[str, Any]) -> tuple[str, str]:
    """Built-in rule evaluators keyed by rule id."""
    if rule_id == "KEYS_MIN_2048":
        if config.get("kind") != "key":
            return NOT_APPLICABLE, "not a key"
        size = config.get("key_size")
        algo = str(config.get("algorithm") or "")
        if algo == "AES":
            return COMPLIANT, "symmetric key"
        if size is None:
            return UNKNOWN, "key size not reported"
        return (COMPLIANT, f"key size {size}") if int(size) >= 2048 \
            else (NON_COMPLIANT, f"key size {size} < 2048")
    if rule_id == "KEYS_ROTATION_REQUIRED":
        if config.get("kind") != "key":
            return NOT_APPLICABLE, "not a key"
        rotation = config.get("rotation_enabled")
        if rotation is None:
            return UNKNOWN, "rotation config not reported"
        return (COMPLIANT, "rotation enabled") if rotation \
            else (NON_COMPLIANT, "rotation disabled")
    if rule_id == "TLS_MIN_1_2":
        if config.get("kind") != "tls":
            return NOT_APPLICABLE, "not a TLS endpoint"
        classification = config.get("classification")
        if classification in (TLS_LEGACY, TLS_WEAK):
            return NON_COMPLIANT, f"endpoint {classification}"
        if classification == "TLS_SECURE":
            return COMPLIANT, "TLS 1.2+"
        return UNKNOWN, "TLS version not reported"
    if rule_id == "CERTS_SHA256_OR_STRONGER":
        if config.get("kind") != "certificate":
            return NOT_APPLICABLE, "not a certificate"
        sig = str(config.get("signature_algorithm") or "").upper()
        if not sig:
            return UNKNOWN, "signature algorithm not reported"
        if any(weak in sig for weak in ("MD5", "SHA1", "SHA-1")):
            return NON_COMPLIANT, f"signature {sig}"
        return COMPLIANT, f"signature {sig}"
    return UNKNOWN, "no evaluator"


def default_rules() -> list[ComplianceRule]:
    """Sector-neutral baseline rules (extensible per sector)."""
    return [
        ComplianceRule(
            rule_id="KEYS_MIN_2048",
            description="Asymmetric keys must be at least 2048-bit",
            controls=["CRYPTO-KEY-STRENGTH"],
            sector="GENERIC",
            severity="HIGH",
        ),
        ComplianceRule(
            rule_id="KEYS_ROTATION_REQUIRED",
            description="Customer-managed keys must have rotation enabled",
            controls=["CRYPTO-KEY-ROTATION"],
            sector="GENERIC",
            severity="MEDIUM",
        ),
        ComplianceRule(
            rule_id="TLS_MIN_1_2",
            description="Public endpoints must terminate TLS 1.2 or newer",
            controls=["CRYPTO-TLS-VERSION"],
            sector="GENERIC",
            severity="HIGH",
        ),
        ComplianceRule(
            rule_id="CERTS_SHA256_OR_STRONGER",
            description="Certificates must use SHA-256 or stronger signatures",
            controls=["CRYPTO-CERT-SIGNATURE"],
            sector="GENERIC",
            severity="HIGH",
        ),
    ]
