"""Context-aware risk classification for CBOM components.

A weak algorithm in a CBOM is a *detection finding*, not a confirmed
production vulnerability. MD5 used to de-duplicate files is not MD5 used to
sign payments; RSA-2048 protecting data that must stay confidential for ten
years has a quantum exposure that RSA-2048 signing a short-lived token does
not. This module states, per component:

* ``algorithm_risk``  — what the algorithm/parameters are, given the recorded
  purpose (HIGH / MEDIUM / LOW / NONE / REVIEW);
* ``priority``        — algorithm risk weighed with business criticality,
  exposure, evidence confidence and how far the evidence reaches (P1–P4);
* ``quantum_exposure`` — how a cryptographically relevant quantum computer
  changes the picture, including harvest-now-decrypt-later for long-lived data;
* the reasons and the factors used, so a reviewer can disagree with the inputs
  instead of with a black-box score.

The inputs are only what the record carries. Missing purpose or criticality
is reported as missing — it never silently defaults to "low".
"""

from __future__ import annotations

from typing import Any

from cbom.crypto_normalization import Normalized

RISK_MODEL_VERSION = "cryptoscan-crypto-risk/1.0.0"
FINDING_STATUS = "DETECTION_FINDING_NOT_CONFIRMED_VULNERABILITY"

_NON_SECURITY_PURPOSES = {
    "CHECKSUM", "FILE_CHECKSUM", "INTEGRITY_CHECKSUM", "CACHE", "CACHE_KEY", "ETAG", "DEDUP",
    "DEDUPLICATION", "NON_SECURITY", "PARTITIONING", "SHARDING", "CONTENT_ADDRESSING"}
_SECURITY_PURPOSES = {
    "SIGNING", "SIGNATURE", "CODE_SIGNING", "PASSWORD", "PASSWORD_HASHING", "CERTIFICATE", "INTEGRITY",
    "AUTH", "AUTHENTICATION", "MAC", "KEY_DERIVATION", "TOKEN"}
_SECURITY_TOKENS = ("SIGN", "PASSWORD", "CERT", "AUTH", "TOKEN", "KEY_DERIV", "KDF", "INTEGRITY", "NONCE")
_ENCRYPT_PURPOSES = {"ENCRYPTION", "DATA_ENCRYPTION", "STORAGE", "DATA_AT_REST", "TRANSPORT", "SESSION",
                     "NETWORK_ENCRYPTION", "PAYMENT", "PIN", "PIN_ENCRYPTION", "KEY_WRAP"}
_LONG_LIVED_CLASSIFICATIONS = {"CONFIDENTIAL", "RESTRICTED", "SECRET", "PCI", "PII", "HIGHLY_CONFIDENTIAL"}
_KEY_ESTABLISHMENT_PURPOSES = {"KEY_EXCHANGE", "KEY_TRANSPORT", "KEY_AGREEMENT", "KEY_WRAP", "TRANSPORT",
                               "SESSION", "ENCRYPTION"}

_SEVERITY_SCORE = {"HIGH": 3.0, "MEDIUM": 2.0, "REVIEW": 1.5, "LOW": 1.0, "NONE": 0.0}


def _key(value: Any) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in str(value or "").upper()).strip("_")


def _years(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def assess(
    n: Normalized,
    *,
    purpose: Any = None,
    criticality: Any = None,
    exposure: Any = None,
    data_classification: Any = None,
    retention_years: Any = None,
    confidence: Any = None,
    deployment_stage: str | None = None,
    hardcoded_key: bool = False,
) -> dict[str, Any]:
    purpose_key = _key(purpose)
    reasons: list[str] = []
    severity = "NONE"

    def raise_to(level: str, why: str) -> None:
        nonlocal severity
        reasons.append(why)
        if _SEVERITY_SCORE[level] > _SEVERITY_SCORE[severity]:
            severity = level

    status = n.registry_status
    family = n.family.upper()

    if n.classification == "UNRECOGNIZED_CANDIDATE":
        raise_to("REVIEW", "algorithm not identified by the registry — confirm it is cryptography before acting")
    elif n.asset_type == "protocol":
        version = n.protocol_version
        if n.family == "SSL" or (n.family in {"TLS", "DTLS"} and version in {"1.0", "1.1"}):
            raise_to("HIGH", f"{n.name} is prohibited (NIST SP 800-52r2, RFC 8996)")
        elif n.family == "TLS" and version == "1.2":
            raise_to("LOW", "TLS 1.2 is permitted with approved cipher suites (NIST SP 800-52r2); "
                            "platform policy prefers TLS 1.3")
        elif n.family in {"TLS", "DTLS"} and version is None and not n.parameter_facts.get("cipher_suite"):
            raise_to("REVIEW", "TLS recorded without a version — negotiated versions not established")
        elif status == "DISALLOWED":
            raise_to("HIGH", n.registry_notes or f"{n.name} is disallowed")
        elif status == "DEPRECATED":
            raise_to("MEDIUM", n.registry_notes or f"{n.name} is deprecated")
    else:
        if family in {"MD5", "SHA-1"}:
            if "HMAC" in purpose_key or purpose_key in {"MAC", "MESSAGE_AUTHENTICATION"}:
                if family == "SHA-1":
                    raise_to("LOW", "SHA-1 recorded inside HMAC; HMAC-SHA-1 does not rely on collision resistance "
                                    "and remains acceptable (SP 800-131A Rev. 2) — prefer SHA-2 on next change")
                else:
                    raise_to("MEDIUM", "HMAC-MD5 is not an approved MAC (SP 800-131A Rev. 2)")
            elif purpose_key in _NON_SECURITY_PURPOSES:
                raise_to("LOW", f"{family} recorded for a non-security purpose ({purpose}); acceptable only "
                                "while no adversary can choose the inputs")
            elif purpose_key in _SECURITY_PURPOSES or any(t in purpose_key for t in _SECURITY_TOKENS):
                raise_to("HIGH", f"{family} is collision-broken and is recorded for a security purpose ({purpose})")
            else:
                raise_to("REVIEW", f"{family} is collision-broken; the recorded purpose ({purpose or 'none'}) does "
                                   "not establish whether it protects anything — confirm before remediating")
        elif family == "3DES" and (purpose_key in _ENCRYPT_PURPOSES or not purpose_key):
            raise_to("HIGH" if purpose_key else "MEDIUM",
                     "TDEA encryption is disallowed after 2023-12-31 (SP 800-131A Rev. 2); only decryption of "
                     "legacy data remains permitted" + ("" if purpose_key else " — recorded purpose does not say which"))
        elif status == "DISALLOWED":
            raise_to("HIGH", n.registry_notes or f"{n.name} is disallowed (NIST SP 800-131A Rev. 2)")
        elif status == "DEPRECATED":
            raise_to("MEDIUM", n.registry_notes or f"{n.name} is deprecated")
        elif status == "RESTRICTED":
            raise_to("LOW", n.registry_notes or f"{n.name} is acceptable only in restricted uses")
        for note in n.notes:
            if "below the" in note:
                raise_to("HIGH", note)
            if note.startswith("XTS"):
                raise_to("LOW", note)
        if n.primitive == "block-cipher" and n.mode == "ecb":
            raise_to("HIGH", "ECB mode leaks plaintext patterns")
    if hardcoded_key:
        raise_to("HIGH", "key material recorded as hard-coded in source")

    # ── quantum exposure ─────────────────────────────────────────────────────
    retention = _years(retention_years)
    classification = _key(data_classification)
    long_lived = (retention is not None and retention >= 5) or classification in _LONG_LIVED_CLASSIFICATIONS
    if n.quantum_level == 0 and family in {"MD5", "SHA-1", "DES", "RC4", "3DES", "RC2"}:
        quantum = "CLASSICALLY_BROKEN"
    elif (n.quantum_level == 0 and n.primitive == "pke" and n.primitive_basis.endswith("PURPOSE_NOT_RECORDED")
          and not purpose_key):
        quantum = "SHOR_VULNERABLE_PURPOSE_NOT_RECORDED"
    elif n.quantum_level == 0 and (n.primitive in {"pke", "key-agree"} or purpose_key in _KEY_ESTABLISHMENT_PURPOSES):
        if long_lived:
            quantum = "HARVEST_NOW_DECRYPT_LATER"
            reasons.append("Shor-vulnerable key establishment protecting long-lived data "
                           f"(retention {retention_years or 'n/a'} years, classification {data_classification or 'n/a'}): "
                           "traffic captured today can be decrypted once a CRQC exists")
        elif retention is None and not classification:
            quantum = "SHOR_VULNERABLE_KEY_ESTABLISHMENT_DATA_LIFETIME_UNKNOWN"
        else:
            quantum = "SHOR_VULNERABLE_KEY_ESTABLISHMENT"
    elif n.quantum_level == 0 and n.primitive == "signature":
        quantum = "SHOR_VULNERABLE_SIGNATURE"
    elif n.primitive in {"kem", "combiner"} or n.family in {"ML-DSA", "SLH-DSA"}:
        quantum = ("QUANTUM_RESISTANT_OBSERVED_AT_RUNTIME" if deployment_stage == "RUNTIME_OBSERVED"
                   else "QUANTUM_RESISTANT_ALGORITHM_DEPLOYMENT_NOT_ESTABLISHED")
    elif n.quantum_level is not None and n.quantum_level >= 1:
        quantum = "GROVER_REDUCED_ACCEPTABLE" if (n.classical_level or 0) >= 128 else "GROVER_REDUCED"
    elif n.asset_type == "protocol":
        quantum = "DEPENDS_ON_NEGOTIATED_ALGORITHMS"
    else:
        quantum = "NOT_ASSESSED"

    # ── business priority ────────────────────────────────────────────────────
    score = _SEVERITY_SCORE[severity]
    factors: dict[str, Any] = {"algorithm_risk": severity}
    crit = _key(criticality)
    if crit in {"CRITICAL", "TIER_0", "TIER0"}:
        score += 1.0
    elif crit in {"HIGH", "TIER_1", "TIER1"}:
        score += 0.5
    factors["business_criticality"] = criticality or "NOT_RECORDED"
    exp = _key(exposure)
    if exp in {"EXTERNAL", "INTERNET", "PUBLIC", "INTERNET_FACING", "PARTNER"}:
        score += 0.5
    factors["exposure"] = exposure or "NOT_RECORDED"
    conf = _key(confidence)
    if conf in {"LOW", "TENTATIVE"}:
        score -= 1.0
    elif conf in {"MEDIUM", "LIKELY"}:
        score -= 0.5
    factors["evidence_confidence"] = confidence or "NOT_RECORDED"
    if deployment_stage == "RUNTIME_OBSERVED":
        score += 0.5
    factors["deployment_stage"] = deployment_stage or "NOT_ESTABLISHED"
    if quantum == "HARVEST_NOW_DECRYPT_LATER":
        # store-now-decrypt-later is a present-day planning risk even when the
        # algorithm is classically sound: it starts at P3, never at NONE.
        score += 2.0
    factors["data_lifetime_years"] = retention_years if retention_years is not None else "NOT_RECORDED"
    if severity == "NONE" and quantum != "HARVEST_NOW_DECRYPT_LATER":
        priority = "NONE"
    elif score >= 4.0:
        priority = "P1"
    elif score >= 3.0:
        priority = "P2"
    elif score >= 2.0:
        priority = "P3"
    else:
        priority = "P4"
    return {
        "algorithm_risk": severity,
        "priority": priority,
        "quantum_exposure": quantum,
        "reasons": reasons,
        "factors": factors,
        "finding_status": FINDING_STATUS,
    }
