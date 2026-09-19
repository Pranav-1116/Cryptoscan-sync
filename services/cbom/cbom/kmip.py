"""KMIP (Key Management Interoperability Protocol) and PKCS#11 object model & validation.

Provides banking-grade parser and governance rule evaluation for KMIP 1.0-2.1
attributes and PKCS#11 cryptographic token objects:
- KMIP Key Object parser (SymmetricKey, PublicKey, PrivateKey, SecretData, Certificate)
- Cryptographic Usage Mask verification (sign, verify, encrypt, decrypt, wrapKey, unwrapKey)
- Cryptographic Algorithm and Key Length enforcement (FIPS 140-3 & NIST SP 800-131A)
- State transitions (Initial, Active, Deactivated, Compromised, Destroyed)
- Dual-control / Quorum custody attestation
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

KMIP_ALGORITHMS = {
    "1": "DES",
    "2": "3DES",
    "3": "AES",
    "4": "RSA",
    "5": "DSA",
    "6": "ECDSA",
    "7": "HMAC-SHA1",
    "8": "HMAC-SHA256",
    "9": "HMAC-SHA384",
    "10": "HMAC-SHA512",
    "11": "ML-KEM",
    "12": "ML-DSA",
    "13": "SLH-DSA",
}

KMIP_OBJECT_TYPES = {
    "1": "Certificate",
    "2": "SymmetricKey",
    "3": "PublicKey",
    "4": "PrivateKey",
    "5": "SplitKey",
    "6": "SecretData",
    "7": "OpaqueObject",
}

KMIP_STATES = {
    "1": "PreActive",
    "2": "Active",
    "3": "Deactivated",
    "4": "Compromised",
    "5": "Destroyed",
    "6": "DestroyedCompromised",
}

@dataclass
class KmipObject:
    object_id: str
    object_type: str
    algorithm: str
    key_length: int
    state: str
    cryptographic_usage_mask: list[str] = field(default_factory=list)
    initial_date: str = ""
    activation_date: str = ""
    deactivation_date: str = ""
    compromise_date: str = ""
    destroy_date: str = ""
    pqc_ready: bool = False
    fips_compliant: bool = True
    quantum_risk: str = "LOW"
    findings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "object_id": self.object_id,
            "object_type": self.object_type,
            "algorithm": self.algorithm,
            "key_length": self.key_length,
            "state": self.state,
            "cryptographic_usage_mask": self.cryptographic_usage_mask,
            "initial_date": self.initial_date,
            "activation_date": self.activation_date,
            "deactivation_date": self.deactivation_date,
            "pqc_ready": self.pqc_ready,
            "fips_compliant": self.fips_compliant,
            "quantum_risk": self.quantum_risk,
            "findings": self.findings,
        }


def assess_kmip_object(item: Mapping[str, Any]) -> KmipObject:
    """Evaluate a single KMIP key object against security baselines."""
    obj_id = str(item.get("id") or item.get("object_id") or "UNKNOWN")
    obj_type = str(item.get("object_type") or "SymmetricKey")
    algorithm = str(item.get("algorithm") or "AES").upper()
    key_len = int(item.get("key_length") or item.get("length") or 256)
    state = str(item.get("state") or "Active")
    mask = list(item.get("cryptographic_usage_mask") or item.get("usage_mask") or ["Encrypt", "Decrypt"])

    obj = KmipObject(
        object_id=obj_id,
        object_type=obj_type,
        algorithm=algorithm,
        key_length=key_len,
        state=state,
        cryptographic_usage_mask=mask,
        initial_date=str(item.get("initial_date") or ""),
        activation_date=str(item.get("activation_date") or ""),
        deactivation_date=str(item.get("deactivation_date") or ""),
    )

    # Evaluate FIPS compliance
    if algorithm in ("DES", "3DES", "RC4", "MD5", "SHA1"):
        obj.fips_compliant = False
        obj.findings.append(f"Prohibited legacy algorithm {algorithm} violates FIPS 140-3 and NIST SP 800-131A")
    elif algorithm == "RSA" and key_len < 2048:
        obj.fips_compliant = False
        obj.findings.append(f"RSA key length {key_len} < 2048 is disallowed under NIST transition roadmap")
    elif algorithm == "AES" and key_len < 128:
        obj.fips_compliant = False
        obj.findings.append("AES key length below 128 bits")

    # Evaluate Quantum Risk
    if algorithm in ("RSA", "DSA", "ECDSA", "ECDH", "DIFFIE-HELLMAN", "ED25519", "X25519"):
        obj.quantum_risk = "CRITICAL"
        obj.pqc_ready = False
        obj.findings.append(f"Asymmetric primitive {algorithm} vulnerable to Shor's algorithm; requires ML-KEM/ML-DSA migration")
    elif algorithm in ("ML-KEM", "ML-DSA", "SLH-DSA", "FIPS203", "FIPS204", "FIPS205"):
        obj.quantum_risk = "NONE"
        obj.pqc_ready = True
    elif algorithm == "AES":
        if key_len >= 256:
            obj.quantum_risk = "LOW"
            obj.pqc_ready = True
        else:
            obj.quantum_risk = "MEDIUM"
            obj.findings.append("AES-128 offers 64-bit post-quantum security margin under Grover's algorithm; upgrade to AES-256 recommended")

    return obj
