"""Deterministic quantum-vulnerability scoring. Policy is never decided here."""

from __future__ import annotations

from typing import Any, Iterable

PKE = {"RSA", "DSA", "DH", "ECDH", "ECDSA", "ED25519", "X25519", "TLS", "TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3"}
BROKEN = {"DES", "3DES", "RC4", "MD5", "SHA-1", "SHA1", "SSLv3", "TLS1.0", "TLS1.1"}
AES128 = {"AES-128", "AES128"}


def classify(algorithm: str | None, *, key_size: int | None = None, purpose: str | None = None) -> dict[str, Any]:
    algo = (algorithm or "UNKNOWN").upper().replace("_", "-")
    if algo in {"AES-128", "AES128"} or (algo == "AES" and key_size and int(key_size) <= 128):
        return {
            "vulnerable": True,
            "category": "symmetric-marginal",
            "estimated_break_year": 2040,
            "harvest_now_decrypt_later_risk": "MEDIUM",
            "notes": "Grover reduces AES-128 to ~64-bit security.",
        }
    if algo.startswith("AES") or algo in {"CHACHA20", "CHACHA20-POLY1305", "XCHACHA20"}:
        return {
            "vulnerable": False,
            "category": "symmetric-strong",
            "estimated_break_year": None,
            "harvest_now_decrypt_later_risk": "LOW",
            "notes": "AES-256 / ChaCha20 remain acceptable under Grover.",
        }
    if algo in BROKEN:
        return {
            "vulnerable": True,
            "category": "classically-broken",
            "estimated_break_year": 2010,
            "harvest_now_decrypt_later_risk": "CRITICAL",
            "notes": "Broken on classical computers already.",
        }
    if algo in PKE or algo.startswith("RSA") or algo.startswith("EC"):
        year = 2030 if (key_size or 2048) <= 2048 else 2035
        return {
            "vulnerable": True,
            "category": "public-key",
            "estimated_break_year": year,
            "harvest_now_decrypt_later_risk": "HIGH",
            "notes": "Shor's algorithm breaks RSA / ECC / DH. Prefer ML-KEM / ML-DSA.",
        }
    if algo in {"ML-KEM", "ML-DSA", "SLH-DSA", "KYBER", "DILITHIUM", "SPHINCS+"}:
        return {
            "vulnerable": False,
            "category": "pqc",
            "estimated_break_year": None,
            "harvest_now_decrypt_later_risk": "LOW",
            "notes": "NIST PQC primitive.",
        }
    return {
        "vulnerable": False,
        "category": "unknown",
        "estimated_break_year": None,
        "harvest_now_decrypt_later_risk": "UNKNOWN",
        "notes": "Insufficient algorithm identity for a quantum call.",
    }


def analyze_quantum_risk(findings: Iterable[dict[str, Any]]) -> dict[str, Any]:
    rows = []
    counts = {"HIGH": 0, "CRITICAL": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for finding in findings:
        info = classify(finding.get("algorithm"), key_size=finding.get("key_size"), purpose=finding.get("purpose"))
        counts[info["harvest_now_decrypt_later_risk"]] = counts.get(info["harvest_now_decrypt_later_risk"], 0) + 1
        rows.append(
            {
                "evidence_id": finding.get("evidence_id") or finding.get("id"),
                "algorithm": finding.get("algorithm"),
                "file_path": finding.get("file_path"),
                "line_number": finding.get("line_number"),
                **info,
            }
        )
    hndl = "CRITICAL" if counts["CRITICAL"] else "HIGH" if counts["HIGH"] else "MEDIUM" if counts["MEDIUM"] else "LOW"
    return {
        "overall_hndl_risk": hndl,
        "vulnerable_count": sum(1 for row in rows if row["vulnerable"]),
        "counts": counts,
        "assets": rows,
        "summary": f"{sum(1 for row in rows if row['vulnerable'])} of {len(rows)} sites are quantum-vulnerable. HNDL risk is {hndl}.",
    }
