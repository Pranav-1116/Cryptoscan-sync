"""CBOM crypto-posture assessment.

Turns a CycloneDX CBOM into an auditable posture report — score, grade,
per-algorithm findings, quantum exposure, and migration recommendations —
using only what the document itself carries (nistDesignation,
cryptoscan:quantum_status — or, in older documents, quantumVulnerable — plus
primitive and oid). Works on CryptoScan-generated CBOMs
and third-party CBOMs alike; when a component lacks cryptoProperties, a
small known-algorithm knowledge base fills the gap.

Scoring (0-100, start from 100):
- DISALLOWED algorithm            -15 each (capped per algorithm family)
- DEPRECATED / RESTRICTED         -8  each
- unknown designation             -4  each
- quantum-vulnerable family       -10 each (families, not occurrences)
Grades: A >= 90, B >= 75, C >= 60, D >= 40, F below.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

# Fallback knowledge base for components without nistDesignation.
KNOWN_ALGORITHMS: dict[str, dict[str, Any]] = {
    "MD5": {"designation": "DISALLOWED", "quantum": False, "primitive": "hash"},
    "SHA-1": {"designation": "DISALLOWED", "quantum": False, "primitive": "hash"},
    "DES": {"designation": "DISALLOWED", "quantum": False, "primitive": "block-cipher"},
    "3DES": {"designation": "DISALLOWED", "quantum": False, "primitive": "block-cipher"},
    "DES-EDE3": {"designation": "DISALLOWED", "quantum": False, "primitive": "block-cipher"},
    "RC4": {"designation": "DISALLOWED", "quantum": False, "primitive": "stream-cipher"},
    "RC2": {"designation": "DISALLOWED", "quantum": False, "primitive": "block-cipher"},
    "RSA": {"designation": "APPROVED", "quantum": True, "primitive": "pke"},
    "ECDSA": {"designation": "APPROVED", "quantum": True, "primitive": "signature"},
    "ECDH": {"designation": "APPROVED", "quantum": True, "primitive": "key-agree"},
    "DSA": {"designation": "DISALLOWED", "quantum": True, "primitive": "signature"},
    "AES": {"designation": "APPROVED", "quantum": False, "primitive": "block-cipher"},
    "AES-GCM": {"designation": "APPROVED", "quantum": False, "primitive": "aead"},
    "CHACHA20-POLY1305": {"designation": "APPROVED", "quantum": False, "primitive": "aead"},
    "SHA-256": {"designation": "APPROVED", "quantum": False, "primitive": "hash"},
    "SHA-384": {"designation": "APPROVED", "quantum": False, "primitive": "hash"},
    "SHA-512": {"designation": "APPROVED", "quantum": False, "primitive": "hash"},
    "SHA3-256": {"designation": "APPROVED", "quantum": False, "primitive": "hash"},
    "HMAC-SHA256": {"designation": "APPROVED", "quantum": False, "primitive": "mac"},
    "ML-KEM": {"designation": "APPROVED", "quantum": False, "primitive": "kem"},
    "ML-DSA": {"designation": "APPROVED", "quantum": False, "primitive": "signature"},
    "SLH-DSA": {"designation": "APPROVED", "quantum": False, "primitive": "signature"},
}

# NIST FIPS 203/204 migration guidance by primitive.
PQC_BY_PRIMITIVE: dict[str, str] = {
    "pke": "ML-KEM-768 (FIPS 203)",
    "kem": "ML-KEM-768 (FIPS 203)",
    "key-agree": "ML-KEM-768 (FIPS 203)",
    "asymmetric": "ML-KEM-768/ML-DSA-65 (FIPS 203/204) for key establishment and signatures",
    "signature": "ML-DSA-65 (FIPS 204)",
    "mac": "HMAC-SHA-384 (larger tags resist quantum forgery cost)",
    "hash": "SHA-256/SHA3-256 (still collision-resistant post-quantum)",
    "block-cipher": "AES-256 (Grover halves effective strength only)",
    "aead": "AES-256-GCM or ChaCha20-Poly1305",
    "stream-cipher": "AES-256-GCM (retire RC4-class ciphers entirely)",
    # Fallback for any unmapped primitive so guidance is never empty.
    "_default": "Adopt NIST PQC (FIPS 203/204) where the primitive is quantum-exposed",
}


def _pqc_guidance(primitive: str | None) -> str:
    if not primitive:
        return PQC_BY_PRIMITIVE["_default"]
    return PQC_BY_PRIMITIVE.get(primitive, PQC_BY_PRIMITIVE["_default"])

LEGACY_REPLACEMENTS: dict[str, str] = {
    "MD5": "SHA-256 (MD5 is collision-broken)",
    "SHA-1": "SHA-256 (SHA-1 is collision-broken)",
    "DES": "AES-256",
    "3DES": "AES-256 (3DES deprecates with 112-bit Sweet32 exposure)",
    "DES-EDE3": "AES-256",
    "RC4": "AES-256-GCM",
    "RC2": "AES-256",
    "DSA": "ECDSA/P--256 now, ML-DSA-65 post-quantum",
}

PENALTIES = {"DISALLOWED": 15, "DEPRECATED": 8, "RESTRICTED": 8, "UNKNOWN": 4}
QUANTUM_FAMILY_PENALTY = 10


def _component_classification(component: dict[str, Any]) -> dict[str, Any]:
    """Resolve (name, primitive, designation, quantum) for one component."""
    crypto = component.get("cryptoProperties") or {}
    algo_props = crypto.get("algorithmProperties") or {}
    name = str(component.get("name") or algo_props.get("algorithm") or "UNKNOWN")
    primitive = (
        crypto.get("primitive")
        or algo_props.get("primitive")
        or KNOWN_ALGORITHMS.get(name.upper(), {}).get("primitive")
        or "unknown"
    )
    designation = str(crypto.get("nistDesignation") or "").upper() or None
    # The document may carry the richer status (cryptoscan:quantum_status) or, in
    # older documents, the legacy boolean. A status that cannot be reduced to a
    # boolean (TRANSITIONAL / UNKNOWN) is left to the knowledge base rather than
    # being read as "safe".
    from cbom import pqc_handoff

    quantum = pqc_handoff.vulnerable_from_component(component)
    if quantum is None:
        quantum = KNOWN_ALGORITHMS.get(name.upper(), {}).get("quantum")
    if designation is None:
        designation = str(
            KNOWN_ALGORITHMS.get(name.upper(), {}).get("designation") or "UNKNOWN"
        )
    return {
        "name": name,
        "primitive": primitive,
        "designation": designation,
        "quantum": bool(quantum),
        "oid": crypto.get("oid"),
        "ref": component.get("bom-ref"),
    }


def assess_cbom(bom: dict[str, Any]) -> dict[str, Any]:
    """Assess the cryptographic posture of a CBOM document."""
    components = [c for c in (bom.get("components") or []) if isinstance(c, dict)]
    classified = [_component_classification(c) for c in components]

    score = 100
    findings: list[dict[str, Any]] = []
    quantum_families: set[str] = set()
    designation_counts: Counter[str] = Counter()
    primitive_counts: Counter[str] = Counter()
    algorithm_counts: Counter[str] = Counter()

    per_algorithm: dict[str, dict[str, Any]] = {}

    for item in classified:
        name = item["name"]
        algorithm_counts[name] += 1
        primitive_counts[item["primitive"]] += 1
        designation_counts[item["designation"]] += 1

        entry = per_algorithm.setdefault(
            name,
            {
                "algorithm": name,
                "occurrences": 0,
                "primitive": item["primitive"],
                "designation": item["designation"],
                "quantum_vulnerable": item["quantum"],
                "oids": set(),
            },
        )
        entry["occurrences"] += 1
        if item["oid"]:
            entry["oids"].add(str(item["oid"]))

        if item["quantum"]:
            quantum_families.add(item["primitive"])

    # Score deductions per algorithm, scaled by concentration: an algorithm
    # that dominates the estate is a bigger problem than a stray occurrence
    # (multiplier = 1 + share of components using it).
    total_components = max(len(classified), 1)
    for name, entry in per_algorithm.items():
        designation = entry["designation"]
        if designation in PENALTIES:
            concentration = 1 + (entry["occurrences"] / total_components)
            score -= PENALTIES[designation] * concentration
            recommendation = LEGACY_REPLACEMENTS.get(name.upper()) or _pqc_guidance(entry["primitive"])
            severity = (
                "high" if designation == "DISALLOWED" else "medium" if designation != "UNKNOWN" else "info"
            )
            findings.append(
                {
                    "algorithm": name,
                    "occurrences": entry["occurrences"],
                    "designation": designation,
                    "severity": severity,
                    "reason": f"{name} is {designation.lower()} by NIST SP 800-131A",
                    "recommendation": recommendation,
                }
            )
        elif entry["quantum_vulnerable"]:
            findings.append(
                {
                    "algorithm": name,
                    "occurrences": entry["occurrences"],
                    "designation": designation,
                    "severity": "medium",
                    "reason": "quantum-vulnerable: breakable by a cryptographically relevant quantum computer",
                    "recommendation": _pqc_guidance(entry["primitive"]),
                }
            )

    score -= QUANTUM_FAMILY_PENALTY * len(quantum_families)
    score = int(round(max(0, min(100, score))))

    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"

    recommendations: list[str] = []
    if quantum_families:
        recommendations.append(
            "Migrate quantum-vulnerable key establishment/signatures ("
            + ", ".join(sorted(quantum_families))
            + ") to "
            + _pqc_guidance(sorted(quantum_families)[0])
        )
    disallowed = [n for n, e in per_algorithm.items() if e["designation"] == "DISALLOWED"]
    if disallowed:
        recommendations.append("Retire broken algorithms immediately: " + ", ".join(sorted(disallowed)))
    unknowns = [n for n, e in per_algorithm.items() if e["designation"] == "UNKNOWN"]
    if unknowns:
        recommendations.append(
            "Classify unknown algorithms via normalization rules: " + ", ".join(sorted(unknowns)[:10])
        )
    if not recommendations:
        recommendations.append("No crypto-posture actions required — maintain continuous CBOM monitoring.")

    meta = (bom.get("metadata") or {}).get("component") or {}
    return {
        "subject": {
            "name": meta.get("name") or bom.get("serialNumber") or "unknown",
            "version": meta.get("version"),
            "serial_number": bom.get("serialNumber"),
            "components": len(components),
        },
        "score": score,
        "grade": grade,
        "summary": {
            "algorithms": dict(algorithm_counts.most_common()),
            "primitives": dict(primitive_counts.most_common()),
            "designations": dict(designation_counts.most_common()),
            "quantum_vulnerable_algorithms": sorted(
                n for n, e in per_algorithm.items() if e["quantum_vulnerable"]
            ),
            "quantum_exposed_families": sorted(quantum_families),
        },
        "findings": sorted(findings, key=lambda f: ({"high": 0, "medium": 1, "info": 2}[f["severity"]], f["algorithm"])),
        "recommendations": recommendations,
        "per_algorithm": [
            {**{k: v for k, v in entry.items() if k != "oids"}, "oids": sorted(entry["oids"])}
            for _, entry in sorted(per_algorithm.items())
        ],
    }
