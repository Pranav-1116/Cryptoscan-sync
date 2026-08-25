"""Map failing findings to concrete replacement guidance."""

from __future__ import annotations

from typing import Any, Iterable

REPLACEMENTS = {
    "DES": ("AES-256-GCM", "Replace DES with AES-256-GCM. ECB/CBC DES cannot be patched in place."),
    "3DES": ("AES-256-GCM", "3DES is retired. Use AES-256-GCM or ChaCha20-Poly1305."),
    "RC4": ("ChaCha20-Poly1305", "RC4 is forbidden. Prefer TLS 1.3 or ChaCha20-Poly1305."),
    "MD5": ("SHA-256", "MD5 is collision-broken. Use SHA-256 or SHA-3."),
    "SHA-1": ("SHA-256", "SHA-1 is retired for signatures and integrity."),
    "SHA1": ("SHA-256", "SHA-1 is retired for signatures and integrity."),
    "RSA": ("ML-KEM-768 / ML-DSA-65", "Plan a hybrid RSA+PQC migration. New key-exchange should be ML-KEM."),
    "DSA": ("ML-DSA-65", "DSA is disallowed. Move to ECDSA-P256 only as an interim, then ML-DSA."),
    "TLS1.0": ("TLS 1.2+", "Disable TLS 1.0/1.1. Require TLS 1.2 minimum, TLS 1.3 preferred."),
    "TLS1.1": ("TLS 1.2+", "Disable TLS 1.0/1.1. Require TLS 1.2 minimum, TLS 1.3 preferred."),
    "SSLv3": ("TLS 1.2+", "SSLv3 is broken (POODLE). Disable immediately."),
}


def suggest_remediations(findings: Iterable[dict[str, Any]]) -> dict[str, Any]:
    suggestions = []
    for finding in findings:
        status = str(finding.get("compliance_status") or "").upper()
        algo = str(finding.get("algorithm") or "UNKNOWN")
        if status not in {"FAIL", "WARN"} and algo not in REPLACEMENTS:
            continue
        replacement, guidance = REPLACEMENTS.get(algo, ("review", "Review this primitive against the current policy pack."))
        if status not in {"FAIL", "WARN"} and algo not in REPLACEMENTS:
            continue
        if status not in {"FAIL", "WARN"}:
            # Only emit unprompted suggestions for known-weak algorithms.
            if algo not in REPLACEMENTS:
                continue
        effort = "high" if algo in {"RSA", "DSA"} else "medium" if algo.startswith("TLS") else "low"
        suggestions.append(
            {
                "evidence_id": finding.get("evidence_id") or finding.get("id"),
                "algorithm": algo,
                "purpose": finding.get("purpose"),
                "file_path": finding.get("file_path"),
                "line_number": finding.get("line_number"),
                "replace_with": replacement,
                "guidance": guidance,
                "effort": effort,
                "label": "AI RECOMMENDATION - NOT COMPLIANCE DETERMINATION" if False else "DETERMINISTIC SUGGESTION - NOT COMPLIANCE DETERMINATION",
            }
        )
    return {
        "count": len(suggestions),
        "suggestions": suggestions,
        "disclaimer": "Remediation text is advisory. Pass/fail comes only from the policy engine.",
    }
