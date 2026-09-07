"""Audit-ready report templates with requirement-by-requirement evaluation.

Six templates (PCI-DSS 4.0, DORA, NIST SP 800-131A, FIPS 140-3, SOC 2,
ISO 27001) plus a custom mode that selects requirements by id. Evaluation
is strictly derived from the policy engine's per-finding rule results —
a requirement with no matching rule evidence reports NOT_EVALUATED, never
a guessed PASS. Templates whose frameworks have no native rule pack (SOC 2,
ISO 27001, DORA) map requirements onto the internal baseline and are
labeled `source: "mapped"` so auditors see the chain of evidence.

Every finished report carries a SHA-256 hash over its canonical JSON —
tamper detection without pretending to a PKI signature (a real digital
signature requires a real certificate; see docs).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable, Mapping

_TEMPLATES: dict[str, dict[str, Any]] = {
    "pci-dss-4.0": {
        "name": "PCI-DSS 4.0 — cryptographic requirements",
        "requirements": [
            {"id": "3.5.1", "title": "Cryptographic inventory is documented and maintained",
             "standard_substrings": ["PCI-DSS 4.0 req. 3.5", "PCI-DSS 4.0 req. 12.3.3"], "rule_prefixes": ["PCIDSS-003"]},
            {"id": "4.2.1", "title": "Strong cryptography during transmission over open networks",
             "standard_substrings": ["PCI-DSS 4.0 req. 4.2", "PCI-DSS 4.0 req. 3.5.1"], "rule_prefixes": ["PCIDSS-002", "PCIDSS-005"]},
            {"id": "8.3.2", "title": "Strong authenticators / no weak algorithm-based access",
             "standard_substrings": ["PCI-DSS 4.0 req. 8.3.2"], "rule_prefixes": ["PCIDSS-004"]},
            {"id": "12.3.3", "title": "Crypto-agile processes for inventory and transitions",
             "standard_substrings": ["PCI-DSS 4.0 req. 12.3.3"], "rule_prefixes": ["PCIDSS-006"]},
            {"id": "3.6.5-pay", "title": "Payment keys: split knowledge / dual control at ceremonies",
             "standard_substrings": ["PCI-DSS 4.0 req. 3.6.5"], "rule_prefixes": ["PAY-003"]},
            {"id": "3.7-pay-rotation", "title": "Payment keys rotated within defined windows",
             "standard_substrings": ["PCI-DSS 4.0 req. 3.7"], "rule_prefixes": ["PAY-002"]},
            {"id": "3.5.1-pay-inventory", "title": "HSM/payment key inventory complete and current",
             "standard_substrings": ["PCI-DSS 4.0 req. 3.5"], "rule_prefixes": ["PAY-005", "PAY-013"]},
            {"id": "3.6-pay-usable", "title": "Retired/compromised keys are not usable",
             "standard_substrings": ["PCI-DSS 4.0 req. 3.6"], "rule_prefixes": ["PAY-009", "PAY-012"]},
        ],
        "source": "native",
    },
    "dora": {
        "name": "DORA — ICT risk & crypto-readiness (mapped)",
        "requirements": [
            {"id": "ICT-31", "title": "ICT risk management includes cryptographic posture",
             "standard_substrings": ["Internal Security Baseline", "NIST SP 800-131A"], "rule_prefixes": ["BASELINE-001", "BASELINE-004"]},
            {"id": "ICT-32", "title": "Crypto transition plan (PQC timeline) exists and is tracked",
             "standard_substrings": ["CNSA"], "rule_prefixes": ["CNSA-001", "CNSA-002", "CNSA-003", "CNSA-004"]},
        ],
        "source": "mapped",
        "mapping_note": "DORA has no native rule pack; requirements are mapped onto the internal baseline and CNSA 2.0 transition rules.",
    },
    "nist-sp-800-131a": {
        "name": "NIST SP 800-131A Rev. 2 — transition requirements",
        "requirements": [
            {"id": "131A-encrypt", "title": "Approved encryption & key sizes",
             "standard_substrings": ["800-131A"], "rule_prefixes": ["NIST131A", "FIPS140-001", "FIPS140-002"]},
            {"id": "131A-digest", "title": "Minimum digest strength / hash transition",
             "standard_substrings": ["800-131A"], "rule_prefixes": ["NIST131A-002", "NIST131A-006", "FIPS140-003"]},
            {"id": "131A-signature", "title": "Digital signature algorithms",
             "standard_substrings": ["800-131A"], "rule_prefixes": ["NIST131A-003", "NIST131A-004", "NIST131A-005"]},
        ],
        "source": "native",
    },
    "fips-140-3": {
        "name": "FIPS 140-3 — approved cryptographic modules/algorithms",
        "requirements": [
            {"id": "140-3-approved", "title": "Only approved algorithms in use",
             "standard_substrings": ["FIPS 140-3"], "rule_prefixes": ["FIPS140-001"]},
            {"id": "140-3-keys", "title": "Key sizes meet FIPS-approved minimums",
             "standard_substrings": ["FIPS 140-3"], "rule_prefixes": ["FIPS140-002"]},
            {"id": "140-3-signatures", "title": "No deprecated signature schemes (SHA-1)",
             "standard_substrings": ["FIPS 140-3"], "rule_prefixes": ["FIPS140-003"]},
        ],
        "source": "native",
    },
    "soc2": {
        "name": "SOC 2 (Trust Services Criteria, mapped)",
        "requirements": [
            {"id": "CC6.1", "title": "Logical security: no forbidden/hardcoded crypto",
             "standard_substrings": ["Internal Security Baseline", "OWASP"], "rule_prefixes": ["BASELINE-001", "BASELINE-004"]},
            {"id": "CC6.7", "title": "Data in transmission protected with strong crypto",
             "standard_substrings": ["800-52", "Internal Security Baseline"], "rule_prefixes": ["BASELINE-005"]},
        ],
        "source": "mapped",
        "mapping_note": "SOC 2 criteria are mapped onto the internal baseline rules; policy remains the only source of pass/fail.",
    },
    "iso-27001": {
        "name": "ISO/IEC 27001:2022 (Annex A, mapped)",
        "requirements": [
            {"id": "A.8.24", "title": "Use of cryptography per policy (Annex A 8.24)",
             "standard_substrings": ["Internal Security Baseline", "NIST SP 800-131A"], "rule_prefixes": ["BASELINE-001", "BASELINE-002", "BASELINE-003"]},
        ],
        "source": "mapped",
        "mapping_note": "Annex A controls are mapped onto the internal baseline rules.",
    },
    "nist-sp-800-53": {
        "name": "NIST SP 800-53 Rev.5 — security & privacy controls (mapped)",
        "requirements": [
            {"id": "AU-9", "title": "Protection of audit information (tamper-evident chain)",
             "standard_substrings": ["audit"], "rule_prefixes": ["BASELINE-002", "AUDIT-001"]},
            {"id": "SC-8", "title": "Transmission confidentiality & integrity (TLS)",
             "standard_substrings": ["800-52", "Internal Security Baseline"], "rule_prefixes": ["BASELINE-005", "TLS-001"]},
            {"id": "SC-12/13", "title": "Cryptographic key establishment / HSM residence",
             "standard_substrings": ["FIPS 140-3", "HSM"], "rule_prefixes": ["FIPS140-001", "FIPS140-002"]},
            {"id": "IA-2", "title": "Federated identification & authentication (SSO/MFA)",
             "standard_substrings": ["Internal Security Baseline"], "rule_prefixes": ["BASELINE-004", "IAM-001"]},
            {"id": "SA-15", "title": "Supply-chain / SBOM & development process",
             "standard_substrings": ["SBOM", "supply chain"], "rule_prefixes": ["SBOM-001", "CVE-001"]},
        ],
        "source": "mapped",
        "mapping_note": "NIST 800-53 controls are mapped onto the internal baseline, TLS/FIPS, IAM, and SBOM rule families; policy remains the only pass/fail source.",
    },
    "uae-pdpl": {
        "name": "UAE Personal Data Protection Law (PDPL) — data-security controls (mapped)",
        "requirements": [
            {"id": "Art.9", "title": "Security of personal data (encryption in transit/at rest)",
             "standard_substrings": ["800-52", "FIPS 140-3"], "rule_prefixes": ["BASELINE-005", "FIPS140-001"]},
            {"id": "Art.10", "title": "Access control to personal data (RBAC/ABAC)",
             "standard_substrings": ["Internal Security Baseline"], "rule_prefixes": ["BASELINE-004", "IAM-001"]},
            {"id": "Art.13", "title": "Personal-data breach notification readiness (alerting)",
             "standard_substrings": ["Internal Security Baseline"], "rule_prefixes": ["BASELINE-001", "ALERT-001"]},
            {"id": "Art.17", "title": "Records / accountability (tamper-evident audit)",
             "standard_substrings": ["audit"], "rule_prefixes": ["AUDIT-001", "BASELINE-002"]},
            {"id": "Art.20", "title": "Transfer security (cryptography for cross-border flows)",
             "standard_substrings": ["800-52", "TLS"], "rule_prefixes": ["TLS-001", "BASELINE-005"]},
        ],
        "source": "mapped",
        "mapping_note": "UAE PDPL articles are mapped onto the internal baseline/TLS/audit rule families; deterministic evidence mapping, no AI.",
    },
}


def template_ids() -> list[str]:
    return sorted(list(_TEMPLATES) + ["custom"])


def template_metadata() -> list[dict[str, Any]]:
    rows = [
        {
            "id": tid,
            "name": spec["name"],
            "source": spec["source"],
            "requirements": [req["id"] for req in spec["requirements"]],
            **({"mapping_note": spec["mapping_note"]} if spec.get("mapping_note") else {}),
        }
        for tid, spec in sorted(_TEMPLATES.items())
    ]
    rows.append(
        {
            "id": "custom",
            "name": "Custom requirement selection",
            "source": "custom",
            "requirements": sorted(
                {req["id"] for spec in _TEMPLATES.values() for req in spec["requirements"]}
            ),
        }
    )
    return rows


def _rule_evidence(findings: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Flatten policy rule results carried on the findings."""
    rows: list[dict[str, Any]] = []
    for finding in findings:
        evaluation = finding.get("policy_evaluation") or {}
        for rule in evaluation.get("rules_evaluated") or []:
            rows.append(
                {
                    "rule_id": str(rule.get("rule_id") or ""),
                    "standard_reference": str(rule.get("standard_reference") or ""),
                    "result": str(rule.get("evaluation_result") or "").upper(),
                    "file_path": finding.get("file_path"),
                    "line_number": finding.get("line_number"),
                    "algorithm": finding.get("algorithm"),
                }
            )
    return rows


def _requirement_matches(rule_row: Mapping[str, Any], requirement: Mapping[str, Any]) -> bool:
    standard = rule_row.get("standard_reference") or ""
    for substring in requirement.get("standard_substrings") or []:
        if substring and substring.lower() in standard.lower():
            return True
    rule_id = rule_row.get("rule_id") or ""
    return any(rule_id.startswith(prefix) for prefix in requirement.get("rule_prefixes") or [])


def evaluate_template(
    findings: Iterable[Mapping[str, Any]],
    template_id: str,
    *,
    requirements: Iterable[str] | None = None,
    extra_evidence: Iterable[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Requirement-by-requirement evaluation from policy evidence alone."""
    if template_id == "custom":
        wanted = [rid for rid in (requirements or []) if rid]
        if not wanted:
            raise ValueError("custom template requires selected requirement ids")
        pool = {}
        for spec in _TEMPLATES.values():
            for requirement in spec["requirements"]:
                pool.setdefault(requirement["id"], requirement)
        selected = []
        for rid in wanted:
            if rid not in pool:
                raise ValueError(f"unknown requirement id '{rid}' (see template metadata)")
            selected.append(pool[rid])
        meta = {"id": "custom", "name": "Custom requirement selection", "source": "custom"}
    else:
        if template_id not in _TEMPLATES:
            raise ValueError(f"unknown template '{template_id}' (expected one of {template_ids()})")
        spec = _TEMPLATES[template_id]
        selected = list(spec["requirements"])
        meta = {"id": template_id, "name": spec["name"], "source": spec["source"]}
        if spec.get("mapping_note"):
            meta["mapping_note"] = spec["mapping_note"]

    evidence = _rule_evidence(findings)
    if extra_evidence:
        # pre-flattened rows (e.g. payment/HSM PAY-xxx findings): same shape,
        # attributed so auditors can trace every requirement to its source
        evidence = evidence + [dict(row) for row in extra_evidence]
    evaluated: list[dict[str, Any]] = []
    for requirement in selected:
        matched = [row for row in evidence if _requirement_matches(row, requirement)]
        failures = [row for row in matched if row["result"] == "FAIL"]
        if not matched:
            status = "NOT_EVALUATED"  # honest: no policy evidence touched this requirement
        elif failures:
            status = "FAIL"
        else:
            status = "PASS"
        evaluated.append(
            {
                "id": requirement["id"],
                "title": requirement["title"],
                "status": status,
                "rules": sorted({row["rule_id"] for row in matched if row["rule_id"]}),
                "evaluated": len(matched),
                "failing": len(failures),
                "failure_locations": sorted(
                    {
                        f"{row['file_path']}:{row['line_number']}"
                        for row in failures
                        if row.get("file_path")
                    }
                )[:20],
            }
        )

    violations = sum(1 for row in evaluated if row["status"] == "FAIL")
    scored = [row for row in evaluated if row["status"] != "NOT_EVALUATED"]
    compliant_pct = (
        round(100.0 * sum(1 for row in scored if row["status"] == "PASS") / len(scored), 1)
        if scored
        else 0.0
    )
    return {
        "template": meta,
        "requirements": evaluated,
        "summary": {
            "total": len(evaluated),
            "pass": sum(1 for row in evaluated if row["status"] == "PASS"),
            "fail": violations,
            "not_evaluated": sum(1 for row in evaluated if row["status"] == "NOT_EVALUATED"),
            "compliant_pct": compliant_pct,
        },
    }


def canonical_hash(payload: Mapping[str, Any]) -> str:
    """SHA-256 over the canonical JSON — tamper detection for the report."""
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def attestation_block(
    *,
    scan: Mapping[str, Any],
    statement: str | None = None,
    policy_pack_hash: str | None = None,
    evidence_count: int = 0,
    generated_by: str = "CryptoScan",
) -> dict[str, Any]:
    return {
        "statement": statement
        or (
            "This report was generated deterministically from stored evidence records. "
            "Compliance status is determined only by the policy engine; no AI or manual "
            "judgement altered any result. The report hash covers the canonical report body."
        ),
        "scope": scan.get("target_location") or scan.get("id") or "unknown scope",
        "scan_id": scan.get("id"),
        "policy_pack_hash": policy_pack_hash,
        "evidence_records": evidence_count,
        "generated_by": generated_by,
        "signature": None,  # PKI signing requires a real certificate — intentionally not faked
    }
