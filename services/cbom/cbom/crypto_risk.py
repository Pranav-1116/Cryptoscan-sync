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
  instead of with a black-box score;
* ``dimensions`` — the same judgement split into independent axes that are
  never collapsed into one word: classical strength, quantum exposure,
  configuration, network exposure, business criticality, migration urgency
  and deployment verification. Every axis carries its own reasons, including
  when it is NONE ("RSA-2048: 112-bit classical security meets the minimum"),
  so "RSA-2048 HIGH" next to "RSA-2048 NONE" is explained, not contradictory.

The inputs are only what the record carries. Missing purpose or criticality
is reported as missing — it never silently defaults to "low".
"""

from __future__ import annotations

from typing import Any

from cbom.crypto_normalization import Normalized

RISK_MODEL_VERSION = "cryptoscan-crypto-risk/2.0.0"
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
    tls: dict[str, Any] | None = None,
    location: Any = None,
) -> dict[str, Any]:
    purpose_key = _key(purpose)
    reasons: list[str] = []
    severity = "NONE"
    axis: dict[str, dict[str, Any]] = {"classical": {"level": "NONE", "reasons": []},
                                       "configuration": {"level": "NONE", "reasons": []}}

    def raise_to(level: str, why: str, dimension: str = "classical") -> None:
        nonlocal severity
        reasons.append(why)
        if _SEVERITY_SCORE[level] > _SEVERITY_SCORE[severity]:
            severity = level
        axis[dimension]["reasons"].append(why)
        bump(level, dimension)

    def bump(level: str, dimension: str) -> None:
        nonlocal severity
        if _SEVERITY_SCORE[level] > _SEVERITY_SCORE[severity]:
            severity = level
        if _SEVERITY_SCORE[level] > _SEVERITY_SCORE[axis[dimension]["level"]]:
            axis[dimension]["level"] = level

    status = n.registry_status
    family = n.family.upper()

    if n.classification == "UNRECOGNIZED_CANDIDATE":
        raise_to("REVIEW", "algorithm not identified by the registry — confirm it is cryptography before acting")
    elif n.asset_type == "protocol" and n.family in {"TLS", "DTLS"} and tls is not None:
        # the observed handshake decides, not the version label
        for why in tls.get("configuration_reasons") or []:
            axis["configuration"]["reasons"].append(why)
            reasons.append(why)
        bump(tls.get("configuration_level") or "REVIEW", "configuration")
        if tls.get("version_status") == "PROHIBITED":
            axis["classical"]["reasons"].append(f"{n.name} is prohibited (RFC 8996; NIST SP 800-52 Rev. 2)")
            bump("HIGH", "classical")
    elif n.asset_type == "protocol":
        version = n.protocol_version
        if n.family == "SSL" or (n.family in {"TLS", "DTLS"} and version in {"1.0", "1.1"}):
            raise_to("HIGH", f"{n.name} is prohibited (NIST SP 800-52r2, RFC 8996)")
        elif n.family == "TLS" and version == "1.2":
            raise_to("REVIEW", "TLS 1.2 is permitted only with approved cipher suites (NIST SP 800-52 Rev. 2); "
                               "no negotiated suite, key exchange or certificate is recorded for this occurrence, "
                               "so it is neither approved nor deprecated", "configuration")
        elif n.family in {"TLS", "DTLS"} and version is None and not n.parameter_facts.get("cipher_suite"):
            raise_to("REVIEW", "TLS recorded without a version — negotiated versions not established",
                     "configuration")
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
                raise_to("LOW", note, "configuration")
        if n.primitive == "block-cipher" and n.mode == "ecb":
            raise_to("HIGH", "ECB mode leaks plaintext patterns", "configuration")
    if hardcoded_key:
        raise_to("HIGH", "key material recorded as hard-coded in source — a configuration finding about how the "
                         "key is stored, not a weakness of the algorithm", "configuration")

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
    dimensions = _dimensions(n, axis, quantum=quantum, purpose_key=purpose_key, criticality=criticality,
                             exposure=exposure, location=location, deployment_stage=deployment_stage,
                             long_lived=long_lived, retention=retention, tls=tls)
    if priority == "NONE" and dimensions["quantum"]["level"] == "HIGH":
        # quantum-only exposure is a planning item, never "no priority"
        priority = "P4"
        factors["quantum_only_priority"] = "Shor-vulnerable key establishment without a classical finding"
    return {
        "algorithm_risk": severity,
        "priority": priority,
        "quantum_exposure": quantum,
        "reasons": reasons,
        "factors": factors,
        "finding_status": FINDING_STATUS,
        "dimensions": dimensions,
        "summary": " · ".join(f"{k} {v['level']}" for k, v in dimensions.items() if k in _SUMMARY_AXES),
    }


_SUMMARY_AXES = ("classical", "quantum", "configuration", "migration_urgency")
_SHOR_MECHANISM = {
    "RSA": "Shor — integer factorisation", "RSA-PSS": "Shor — integer factorisation",
    "RSA-OAEP": "Shor — integer factorisation", "DSA": "Shor — finite-field discrete log",
    "DH": "Shor — finite-field discrete log", "DHE": "Shor — finite-field discrete log",
    "ECDH": "Shor — elliptic-curve discrete log", "ECDHE": "Shor — elliptic-curve discrete log",
    "ECDSA": "Shor — elliptic-curve discrete log", "EDDSA": "Shor — elliptic-curve discrete log",
    "ED25519": "Shor — elliptic-curve discrete log", "ED448": "Shor — elliptic-curve discrete log",
    "X25519": "Shor — elliptic-curve discrete log", "X448": "Shor — elliptic-curve discrete log",
    "ECIES": "Shor — elliptic-curve discrete log",
}
_EXPOSURE_LEVEL = {"EXTERNAL": "HIGH", "INTERNET": "HIGH", "PUBLIC": "HIGH", "INTERNET_FACING": "HIGH",
                   "PARTNER": "MEDIUM", "THIRD_PARTY": "MEDIUM", "INTERNAL": "LOW", "PRIVATE": "LOW",
                   "ISOLATED": "NONE", "AIR_GAPPED": "NONE"}
_CRITICALITY_LEVEL = {"CRITICAL": "CRITICAL", "TIER_0": "CRITICAL", "TIER0": "CRITICAL", "HIGH": "HIGH",
                      "TIER_1": "HIGH", "TIER1": "HIGH", "MEDIUM": "MEDIUM", "TIER_2": "MEDIUM", "LOW": "LOW",
                      "TIER_3": "LOW"}


def _classical_none_reason(n: Normalized) -> str:
    """Why the classical axis is NONE — stated, never left blank."""
    level = n.classical_level
    if n.asset_type == "protocol":
        return f"{n.name}: no classical weakness recorded for the protocol version"
    if level is None:
        return (f"{n.name}: registry status {n.registry_status}; no classical weakness recorded "
                "(security level not established from the evidence)")
    if level >= 128:
        return f"{n.name}: {level}-bit classical security (NIST SP 800-57 Pt1 Rev. 5) — above the 112-bit minimum"
    if level >= 112:
        return (f"{n.name}: {level}-bit classical security meets the 112-bit minimum (SP 800-57 Pt1 Rev. 5; "
                "acceptable through 2030 per SP 800-131A Rev. 2; NIST IR 8547 draft deprecates 112-bit after 2030)")
    return f"{n.name}: {level}-bit classical security"


def _dimensions(n: Normalized, axis: dict[str, dict[str, Any]], *, quantum: str, purpose_key: str,
                criticality: Any, exposure: Any, location: Any, deployment_stage: str | None,
                long_lived: bool, retention: float | None, tls: dict[str, Any] | None) -> dict[str, Any]:
    classical = {"level": axis["classical"]["level"], "reasons": list(axis["classical"]["reasons"])}
    if classical["level"] == "NONE":
        classical["reasons"] = [_classical_none_reason(n)]
    configuration = {"level": axis["configuration"]["level"], "reasons": list(axis["configuration"]["reasons"])
                     or ["no configuration weakness recorded (key storage, mode and protocol settings as detected)"]}
    if tls is not None:
        configuration["facts_not_recorded"] = tls.get("facts_not_recorded") or []

    # ── quantum: Shor exposure is stated separately from its urgency ─────────
    family = n.family.upper()
    shor = n.quantum_level == 0 and (family in _SHOR_MECHANISM or n.quantum_impact == "shor")
    mechanism = _SHOR_MECHANISM.get(family) if shor else None
    q_reasons: list[str] = []
    if quantum == "CLASSICALLY_BROKEN":
        q_level = "LOW"
        q_reasons.append(f"{n.name} is already classically broken; quantum adds nothing — the classical finding "
                         "decides remediation")
    elif quantum == "HARVEST_NOW_DECRYPT_LATER":
        q_level = "HIGH"
        q_reasons.append(f"{mechanism or 'Shor'} breaks {n.name}; long-lived data makes recorded traffic "
                         "decryptable later (harvest-now-decrypt-later)")
    elif quantum.startswith("SHOR_VULNERABLE_KEY_ESTABLISHMENT") or quantum == "SHOR_VULNERABLE_PURPOSE_NOT_RECORDED":
        short_lived = retention is not None and retention < 5 and not long_lived
        q_level = "MEDIUM" if short_lived else "HIGH"
        q_reasons.append(f"{mechanism or 'Shor'} breaks {n.name} " + (
            "but the recorded data lifetime is short" if short_lived else
            "and the protected data lifetime is not recorded, so harvest-now-decrypt-later cannot be excluded"))
    elif quantum == "SHOR_VULNERABLE_SIGNATURE":
        long_sig = any(t in purpose_key for t in ("CODE_SIGN", "FIRMWARE", "ROOT", "CA", "CERTIFICATE", "AUDIT"))
        q_level = "HIGH" if long_sig else "MEDIUM"
        q_reasons.append(f"{mechanism or 'Shor'} breaks {n.name}: signatures become forgeable once a CRQC exists"
                         + (" and this purpose relies on long-lived signatures" if long_sig else
                            "; no retroactive exposure of past data"))
    elif quantum.startswith("QUANTUM_RESISTANT"):
        q_level = "NONE"
        q_reasons.append(f"{n.name} is a standardized post-quantum algorithm ({n.standard or 'NIST PQC'})")
    elif quantum == "GROVER_REDUCED_ACCEPTABLE":
        q_level = "NONE"
        q_reasons.append(f"Grover at most halves {n.name}'s {n.classical_level}-bit strength; remains adequate")
    elif quantum == "GROVER_REDUCED":
        q_level = "LOW"
        q_reasons.append(f"Grover reduces {n.name} below a 128-bit classical margin; prefer 256-bit keys/digests")
    elif quantum == "DEPENDS_ON_NEGOTIATED_ALGORITHMS":
        if tls is not None:
            q_level = tls.get("quantum_level") or "REVIEW"
            q_reasons += list(tls.get("quantum_reasons") or [])
        else:
            q_level = "REVIEW"
            q_reasons.append("protocol exposure depends on the negotiated key exchange and certificate, which are not "
                             "recorded for this occurrence")
    elif n.primitive in {"mac"} or family.startswith("HMAC"):
        q_level = "NONE"
        q_reasons.append(f"{n.name}: keyed MAC; Grover's effect is bounded by the key length")
    else:
        q_level = "REVIEW"
        q_reasons.append("quantum exposure not assessed for this primitive")
    quantum_axis = {"level": q_level, "exposure": quantum, "shor_exposed": bool(shor),
                    "mechanism": mechanism or ("Grover — quadratic search speed-up" if n.quantum_impact == "grover"
                                               or (n.quantum_level or 0) >= 1 else None),
                    "reasons": q_reasons}
    if shor and family in {"ECDSA", "ECDH", "ECDHE", "EDDSA", "ECIES"}:
        quantum_axis["curve"] = n.curve or "NOT_RECORDED"
        quantum_axis["curve_note"] = ("Shor breaks every elliptic curve in use (P-256, P-384, X25519 …); the curve "
                                      "changes classical strength only, never the quantum exposure")

    # ── network exposure ────────────────────────────────────────────────────
    exp = _key(exposure)
    loc = str(location or "")
    if exp in _EXPOSURE_LEVEL:
        exposure_axis = {"level": _EXPOSURE_LEVEL[exp], "basis": "RECORDED_EXPOSURE", "value": exposure}
    elif loc.startswith(("tls://", "dtls://", "ssh://")):
        exposure_axis = {"level": "NOT_RECORDED", "basis": "NETWORK_ENDPOINT_OBSERVED",
                         "value": "reachable network listener; internet/partner exposure not recorded"}
    else:
        exposure_axis = {"level": "NOT_RECORDED", "basis": "NO_EXPOSURE_RECORDED",
                         "value": "exposure of the owning system is not recorded"}

    crit = _CRITICALITY_LEVEL.get(_key(criticality))
    business_axis = {"level": crit or "NOT_RECORDED",
                     "basis": "OWNING_SYSTEM_CRITICALITY" if crit else "NO_OWNING_SYSTEM_CRITICALITY"}

    # ── migration urgency ───────────────────────────────────────────────────
    worst_now = max(classical["level"], configuration["level"], key=lambda x: _SEVERITY_SCORE[x])
    critical = crit in {"CRITICAL", "HIGH"}
    if worst_now == "HIGH":
        urgency, why = "IMMEDIATE", "classically weak or misconfigured today — remediation does not wait for quantum"
    elif q_level == "HIGH" and (critical or long_lived):
        urgency, why = "HIGH", ("quantum-vulnerable on a critical system or long-lived data; NIST IR 8547 (draft) "
                                "disallows quantum-vulnerable public-key algorithms after 2035 — plan this cycle")
    elif worst_now == "MEDIUM" or q_level == "HIGH":
        urgency, why = "MEDIUM", ("quantum-vulnerable key establishment" if q_level == "HIGH" else
                                  "classical/configuration finding of medium severity")
    elif q_level == "MEDIUM":
        urgency, why = ("MEDIUM" if critical else "LOW"), "quantum-vulnerable signature: migrate before CRQC; no HNDL"
    elif worst_now == "REVIEW" or q_level == "REVIEW":
        urgency, why = "REVIEW", "inputs missing — confirm purpose/configuration before scheduling"
    elif worst_now == "LOW" or q_level == "LOW":
        urgency, why = "LOW", "minor finding; fix on next change"
    else:
        urgency, why = "NONE", "no classical, configuration or quantum driver"
    urgency_axis = {"level": urgency, "reasons": [why],
                    "inputs": {"classical": classical["level"], "configuration": configuration["level"],
                               "quantum": q_level, "business_criticality": business_axis["level"],
                               "long_lived_data": long_lived}}

    stage = deployment_stage or "NOT_ESTABLISHED"
    verified = stage == "RUNTIME_OBSERVED"
    deployment_axis = {
        "level": "OBSERVED_AT_RUNTIME" if verified else "NOT_VERIFIED",
        "stage": stage,
        "reasons": ["observed by a runtime collector (handshake/process); still not human-approved"] if verified else
                   [f"{stage.replace('_', ' ').lower()}: static detection is not proof the algorithm is deployed or used"],
    }
    return {"classical": classical, "quantum": quantum_axis, "configuration": configuration,
            "exposure": exposure_axis, "business_criticality": business_axis, "migration_urgency": urgency_axis,
            "deployment_verification": deployment_axis}
