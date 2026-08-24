"""
Cryptographic agility score.

A site is "hardcoded" when the algorithm is a string literal baked into
source (Cipher.getInstance("DES/ECB/...")). Those sites cannot be
retargeted without a code change. Factory / config-driven sites score
higher because a PQC or AES-GCM swap is a configuration change.

Score is 0–100. Policy is never decided here — this is an engineering
metric for migration planning.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping


_HARDCODED_REASONS = {
    "literal-api",
    "hardcoded-transformation",
    "string-literal",
}

_FACTORY_REASONS = {
    "factory",
    "variable-algorithm",
    "config-driven",
    "provider-lookup",
}


def _reason(finding: Mapping[str, Any]) -> str:
    metadata = (finding.get("finding_data") or {}).get("metadata") or {}
    return str(
        finding.get("confidence_reason")
        or metadata.get("confidence_reason")
        or ""
    ).lower()


def _raw_transformation(finding: Mapping[str, Any]) -> str:
    crypto = (finding.get("finding_data") or {}).get("crypto") or {}
    return str(finding.get("raw_transformation") or crypto.get("raw_transformation") or "")


def is_hardcoded_site(finding: Mapping[str, Any]) -> bool:
    if finding.get("is_hardcoded_key"):
        return True
    reason = _reason(finding)
    if any(token in reason for token in _HARDCODED_REASONS):
        return True
    raw = _raw_transformation(finding)
    if raw and ("/" in raw or raw.upper() in {"DES", "DESEDE", "RC4", "MD5", "SHA-1", "SHA1"}):
        return True
    return False


def is_factory_site(finding: Mapping[str, Any]) -> bool:
    reason = _reason(finding)
    if any(token in reason for token in _FACTORY_REASONS):
        return True
    algorithm = str(finding.get("algorithm") or "").upper()
    confidence = str(finding.get("confidence") or "").upper()
    return algorithm in {"", "UNKNOWN"} or confidence == "LOW"


def compute_agility(findings: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    rows = list(findings)
    total = len(rows)
    hardcoded = [row for row in rows if is_hardcoded_site(row)]
    factory = [row for row in rows if is_factory_site(row)]
    failing = [row for row in rows if str(row.get("compliance_status") or "").upper() == "FAIL"]
    hardcoded_fails = [row for row in hardcoded if row in failing or str(row.get("compliance_status") or "").upper() == "FAIL"]

    if total == 0:
        score = 100.0
    else:
        # Weight: hardcoded FAIL sites hurt the most; factory sites recover points.
        penalty = (len(hardcoded) / total) * 45.0 + (len(failing) / total) * 40.0
        bonus = (len(factory) / total) * 15.0
        score = max(0.0, min(100.0, 100.0 - penalty + bonus))

    band = "high" if score >= 75 else "medium" if score >= 45 else "low"
    return {
        "score": round(score, 1),
        "band": band,
        "total_sites": total,
        "hardcoded_sites": len(hardcoded),
        "factory_sites": len(factory),
        "failing_sites": len(failing),
        "hardcoded_failing_sites": len(hardcoded_fails),
        "summary": (
            f"{len(hardcoded)}/{total} sites bake the algorithm into source; "
            f"{len(failing)} fail policy. Agility is {band} ({round(score, 1)})."
        ),
    }
