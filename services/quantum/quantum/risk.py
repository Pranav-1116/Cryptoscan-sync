"""Deterministic quantum-vulnerability scoring. Policy is never decided here."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


from collections.abc import Iterable, Mapping
from datetime import date, datetime, timezone
from typing import Any

PKE = {"RSA", "DSA", "DH", "ECDH", "ECDSA", "ED25519", "X25519", "TLS", "TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3"}
BROKEN = {"DES", "3DES", "RC4", "MD5", "SHA-1", "SHA1", "SSLV3", "TLS1.0", "TLS1.1"}
SHOR = {"RSA", "DSA", "DH", "ECDH", "ECDSA", "ED25519", "X25519"}
PQC = {"ML-KEM", "ML-DSA", "SLH-DSA", "KYBER", "DILITHIUM", "SPHINCS+", "ML-KEM-768", "ML-KEM-1024", "ML-DSA-65", "ML-DSA-87"}

PQC_REPLACEMENTS = {
    "RSA": {"key_exchange": "ML-KEM-768", "signing": "ML-DSA-65", "hybrid": True},
    "ECDH": {"key_exchange": "ML-KEM-768", "signing": None, "hybrid": True},
    "ECDSA": {"key_exchange": None, "signing": "ML-DSA-65", "hybrid": True},
    "DH": {"key_exchange": "ML-KEM-768", "signing": None, "hybrid": True},
    "DSA": {"key_exchange": None, "signing": "ML-DSA-65", "hybrid": True},
    "AES-128": {"encryption": "AES-256", "hybrid": False},
    "SHA-256": {"hash": "SHA-384", "hybrid": False},
}

QUANTUM_THREAT_YEAR = 2030
CALC_VERSION = "quantum-risk-v2.0"


def _algo(algorithm: str | None) -> str:
    return (algorithm or "UNKNOWN").upper().replace("_", "-")


def classify(algorithm: str | None, *, key_size: int | None = None, purpose: str | None = None) -> dict[str, Any]:
    algo = _algo(algorithm)
    if algo in {"AES-128", "AES128"} or (algo == "AES" and key_size and int(key_size) <= 128):
        return {
            "vulnerable": True,
            "category": "symmetric-marginal",
            "estimated_break_year": 2040,
            "harvest_now_decrypt_later_risk": "MEDIUM",
            "notes": "Grover reduces AES-128 to ~64-bit security.",
            "threat_type": "GROVER_WEAKENED",
            "base_vulnerability": 50,
            "recommended_replacement": "AES-256",
            "hybrid_mode_recommended": False,
        }
    if algo.startswith("AES") or algo in {"CHACHA20", "CHACHA20-POLY1305", "XCHACHA20"}:
        return {
            "vulnerable": False,
            "category": "symmetric-strong",
            "estimated_break_year": None,
            "harvest_now_decrypt_later_risk": "LOW",
            "notes": "AES-256 / ChaCha20 remain acceptable under Grover.",
            "threat_type": "GROVER_MINIMAL",
            "base_vulnerability": 10,
            "recommended_replacement": None,
            "hybrid_mode_recommended": False,
        }
    if algo in BROKEN:
        return {
            "vulnerable": True,
            "category": "classically-broken",
            "estimated_break_year": 2010,
            "harvest_now_decrypt_later_risk": "CRITICAL",
            "notes": "Broken on classical computers already.",
            "threat_type": "CLASSICALLY_BROKEN",
            "base_vulnerability": 100,
            "recommended_replacement": "AES-256-GCM" if "AES" not in algo else "AES-256",
            "hybrid_mode_recommended": False,
        }
    if algo in PQC or any(algo.startswith(token) for token in ("ML-KEM", "ML-DSA", "SLH-DSA")):
        return {
            "vulnerable": False,
            "category": "pqc",
            "estimated_break_year": None,
            "harvest_now_decrypt_later_risk": "LOW",
            "notes": "NIST PQC primitive.",
            "threat_type": "PQC_RESISTANT",
            "base_vulnerability": 0,
            "recommended_replacement": None,
            "hybrid_mode_recommended": False,
        }
    if algo in PKE or algo.startswith("RSA") or algo.startswith("EC"):
        year = 2030 if (key_size or 2048) <= 2048 else 2035
        rec = recommended_replacement(algo, purpose=purpose)
        return {
            "vulnerable": True,
            "category": "public-key",
            "estimated_break_year": year,
            "harvest_now_decrypt_later_risk": "HIGH",
            "notes": "Shor's algorithm breaks RSA / ECC / DH. Prefer ML-KEM / ML-DSA.",
            "threat_type": "SHOR_VULNERABLE",
            "base_vulnerability": 100,
            "recommended_replacement": rec.get("algorithm"),
            "hybrid_mode_recommended": True,
        }
    if algo.startswith("SHA-256") or algo == "SHA256":
        return {
            "vulnerable": True,
            "category": "hash-marginal",
            "estimated_break_year": 2040,
            "harvest_now_decrypt_later_risk": "MEDIUM",
            "notes": "Grover reduces SHA-256 collision resistance.",
            "threat_type": "GROVER_WEAKENED",
            "base_vulnerability": 40,
            "recommended_replacement": "SHA-384",
            "hybrid_mode_recommended": False,
        }
    return {
        "vulnerable": False,
        "category": "unknown",
        "estimated_break_year": None,
        "harvest_now_decrypt_later_risk": "UNKNOWN",
        "notes": "Insufficient algorithm identity for a quantum call.",
        "threat_type": "UNKNOWN",
        "base_vulnerability": 75,
        "recommended_replacement": None,
        "hybrid_mode_recommended": False,
    }


def recommended_replacement(algorithm: str | None, *, purpose: str | None = None) -> dict[str, Any]:
    algo = _algo(algorithm)
    family = "RSA" if algo.startswith("RSA") else "ECDH" if "DH" in algo else "ECDSA" if algo.startswith("EC") else algo
    table = PQC_REPLACEMENTS.get(family) or PQC_REPLACEMENTS.get(algo) or {}
    purpose_u = (purpose or "").upper()
    if "SIGN" in purpose_u:
        choice = table.get("signing") or table.get("key_exchange") or "ML-DSA-65"
    elif "ENCRYPT" in purpose_u or "KEY" in purpose_u or "TLS" in purpose_u or "EXCHANGE" in purpose_u:
        choice = table.get("key_exchange") or table.get("encryption") or "ML-KEM-768"
    else:
        choice = table.get("key_exchange") or table.get("signing") or table.get("encryption") or table.get("hash")
    return {
        "algorithm": choice,
        "hybrid": bool(table.get("hybrid")),
        "rationale": "NIST FIPS 203/204/205 transition; hybrid recommended for public-key primitives.",
    }


def hndl_risk(
    *,
    algorithm: str | None,
    purpose: str | None = None,
    retention_years: int | None = None,
    public_network: bool = True,
    regulated: bool = False,
    classifications: Iterable[str] | None = None,
) -> dict[str, Any]:
    info = classify(algorithm, purpose=purpose)
    if info["threat_type"] not in {"SHOR_VULNERABLE", "CLASSICALLY_BROKEN"}:
        return {"hndl_risk": "NONE", "score_multiplier": 1.0, "reason": "Not asymmetric harvestable ciphertext."}
    years = int(retention_years or 0)
    if years >= 25:
        level, mult = "CRITICAL", 1.5
    elif years >= 10:
        level, mult = "HIGH", 1.2
    elif years >= 5:
        level, mult = "MODERATE", 1.1
    else:
        level, mult = "LOW", 1.0
    if not public_network:
        mult *= 0.8
    classes = {str(item).upper() for item in (classifications or [])}
    if regulated or classes & {"PHI", "HIPAA", "GDPR", "CLASSIFIED", "PAN", "PCI", "PCI-DSS"}:
        mult *= 1.5
        if years >= 10:
            level = "CRITICAL"
    return {"hndl_risk": level, "score_multiplier": round(mult, 3), "reason": f"retention={years}y regulated={regulated}"}


def migration_deadline(
    *,
    scopes: Iterable[str] | None = None,
    retention_years: int | None = None,
    today: date | None = None,
) -> dict[str, Any]:
    today = today or datetime.now(timezone.utc).date()
    deadlines: list[tuple[str, date]] = [("quantum_threat", date(QUANTUM_THREAT_YEAR, 1, 1))]
    for scope in scopes or []:
        token = str(scope).upper()
        if "DORA" in token:
            deadlines.append(("regulatory:DORA", date(2025, 1, 17)))
        if "CNSA" in token or "NSA" in token:
            deadlines.append(("regulatory:NSA-CNSA-2.0", date(2033, 1, 1)))
        if "PCI" in token:
            deadlines.append(("regulatory:PCI-DSS", date(2025, 4, 1)))
    if (retention_years or 0) >= 10:
        deadlines.append(("hndl", date(today.year + 2, today.month, today.day)))
    else:
        deadlines.append(("hndl", date(today.year + 5, today.month, min(today.day, 28))))
    label, when = min(deadlines, key=lambda item: item[1])
    days = (when - today).days
    if days <= 180:
        urgency = "IMMEDIATE"
    elif days <= 365:
        urgency = "URGENT"
    elif days <= 365 * 3:
        urgency = "1-2 YEARS"
    else:
        urgency = "3-5 YEARS"
    return {
        "deadline_date": when.isoformat(),
        "days_remaining": days,
        "urgency": urgency,
        "reason": label,
        "candidates": [{"reason": name, "date": value.isoformat()} for name, value in deadlines],
    }


def score_asset(
    asset: Mapping[str, Any],
    *,
    system: Mapping[str, Any] | None = None,
    today: date | None = None,
    sector_criticality_weight: float | None = None,
) -> dict[str, Any]:
    system = system or {}
    extra = system.get("extra") or {}
    algo = asset.get("algorithm")
    key_size = asset.get("key_size")
    purpose = asset.get("purpose")
    info = classify(algo, key_size=key_size, purpose=purpose)
    classes = list(system.get("data_classifications") or extra.get("data_classifications") or [])
    scopes = list(system.get("compliance_scopes") or [])
    retention = extra.get("data_retention_years")
    if retention is None:
        retention = system.get("data_retention_years")
    public = str(extra.get("network_type") or "PUBLIC_INTERNET").upper() in {"PUBLIC_INTERNET", "INTERNET", "PUBLIC"}
    regulated = bool(set(c.upper() for c in classes) & {"PHI", "PAN", "PCI", "PCI-DSS", "CLASSIFIED", "HIPAA"})
    hndl = hndl_risk(
        algorithm=algo,
        purpose=purpose,
        retention_years=int(retention or 0),
        public_network=public,
        regulated=regulated,
        classifications=classes,
    )
    sensitivity = 1.0
    upper = {str(item).upper() for item in classes}
    if "CLASSIFIED" in upper:
        sensitivity = 2.0
    elif upper & {"PAN", "PHI", "PCI", "PCI-DSS"}:
        sensitivity = 1.5
    years_until = QUANTUM_THREAT_YEAR - (today or datetime.now(timezone.utc).date()).year
    if years_until <= 2:
        timeline = 2.0
    elif years_until <= 5:
        timeline = 1.5
    elif years_until <= 10:
        timeline = 1.2
    else:
        timeline = 1.0
    tier = str(system.get("criticality") or extra.get("criticality_tier") or extra.get("criticality") or "").upper()
    crit = 1.5 if "1" in tier or tier in {"CRITICAL", "MISSION_CRITICAL", "TIER-1", "VERY_HIGH"} else 1.2 if "2" in tier or tier in {"HIGH"} else 1.0
    # Sector layer can supply a finer, deterministic weight (0.7..1.5) derived
    # from the sector profile + asset signals; it overrides the coarse tier.
    if sector_criticality_weight is not None:
        crit = max(0.5, min(1.5, float(sector_criticality_weight)))
    score = min(
        100,
        int(
            round(
                float(info.get("base_vulnerability") or 0)
                * sensitivity
                * float(hndl.get("score_multiplier") or 1.0)
                * timeline
                * crit
            )
        ),
    )
    if score >= 80:
        risk_category, urgency = "CRITICAL", "IMMEDIATE"
    elif score >= 60:
        risk_category, urgency = "HIGH", "1-2 YEARS"
    elif score >= 40:
        risk_category, urgency = "MEDIUM", "3-5 YEARS"
    elif score >= 20:
        risk_category, urgency = "LOW", "5-10 YEARS"
    else:
        risk_category, urgency = "MINIMAL", "NO ACTION NEEDED"
    deadline = migration_deadline(scopes=scopes, retention_years=int(retention or 0), today=today)
    rec = recommended_replacement(algo, purpose=purpose)
    payload = {
        "quantum_risk_score": score,
        "risk_category": risk_category,
        "threat_type": info.get("threat_type"),
        "base_vulnerability": info.get("base_vulnerability"),
        "hndl_risk": hndl.get("hndl_risk"),
        "data_sensitivity": "HIGH" if sensitivity >= 1.5 else "MEDIUM" if sensitivity > 1 else "LOW",
        "migration_deadline": deadline["deadline_date"],
        "days_until_deadline": deadline["days_remaining"],
        "urgency": deadline["urgency"] if info.get("vulnerable") else urgency,
        "recommended_replacement": rec.get("algorithm") or info.get("recommended_replacement"),
        "hybrid_mode_recommended": bool(rec.get("hybrid") or info.get("hybrid_mode_recommended")),
        "calculation_version": CALC_VERSION,
        **{k: v for k, v in info.items()},
    }
    return payload


def _sector_weight(sector: str | None, finding: Mapping[str, Any], system: Mapping[str, Any] | None) -> float | None:
    """Derive a deterministic criticality weight from the sector profile.

    Soft-imports sector_profiles (a sibling service); returns None if the
    package is unavailable so quantum scoring still works standalone.
    """
    if not sector:
        return None
    try:
        from sector_profiles import get_profile, risk_weight, score_criticality
    except Exception as _handler_exc:
        logger.warning(
            "exception_suppressed",
            extra={"error_type": type(_handler_exc).__name__},
        )
        return None
    system = system or {}
    extra = system.get("extra") or {}
    asset_type = (
        finding.get("asset_type")
        or system.get("asset_type")
        or system.get("name")
        or "system"
    )
    signals = {
        "environment": system.get("environment") or extra.get("environment") or "production",
        "payment_path": bool(extra.get("payment_path")),
        "safety_critical": bool(extra.get("safety_critical")),
        "handles_pii": bool(extra.get("handles_pii")),
        "internet_exposed": bool(extra.get("network_type") in {"PUBLIC_INTERNET", "INTERNET", "PUBLIC"}),
        "downstream_count": int(extra.get("downstream_count", 0) or 0),
    }
    tier = score_criticality(get_profile(sector), str(asset_type), **signals)
    return risk_weight(tier)


def analyze_quantum_risk(
    findings: Iterable[dict[str, Any]],
    *,
    systems: Iterable[Mapping[str, Any]] | None = None,
    today: date | None = None,
    sector: str | None = None,
) -> dict[str, Any]:
    system_by_id = {str(row.get("id") or ""): row for row in (systems or [])}
    rows = []
    counts = {"HIGH": 0, "CRITICAL": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0, "NONE": 0}
    pqc = 0
    for finding in findings:
        system = system_by_id.get(str(finding.get("system_id") or "")) or finding.get("system")
        weight = _sector_weight(sector, finding, system)
        info = score_asset(finding, system=system, today=today, sector_criticality_weight=weight)
        hndl_level = info.get("harvest_now_decrypt_later_risk") or info.get("hndl_risk") or "UNKNOWN"
        counts[hndl_level] = counts.get(hndl_level, 0) + 1
        if info.get("threat_type") == "PQC_RESISTANT":
            pqc += 1
        rows.append(
            {
                "evidence_id": finding.get("evidence_id") or finding.get("id"),
                "algorithm": finding.get("algorithm"),
                "file_path": finding.get("file_path"),
                "line_number": finding.get("line_number"),
                **info,
            }
        )
    hndl = (
        "CRITICAL"
        if counts.get("CRITICAL")
        else "HIGH"
        if counts.get("HIGH")
        else "MEDIUM"
        if counts.get("MEDIUM")
        else "LOW"
    )
    vulnerable = sum(1 for row in rows if row.get("vulnerable"))
    return {
        "overall_hndl_risk": hndl,
        "vulnerable_count": vulnerable,
        "pqc_ready_count": pqc,
        "counts": counts,
        "assets": rows,
        "sector": sector,
        "sector_weighted": bool(sector),
        "summary": f"{vulnerable} of {len(rows)} sites are quantum-vulnerable. HNDL risk is {hndl}.",
        "calculation_version": CALC_VERSION,
    }
