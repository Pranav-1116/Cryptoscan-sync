"""§2 Cryptographic algorithm registry — versioned against current standards.

Extends ``shared_models.algorithm_registry`` (canonical names, key sizes,
NIST verdicts, quantum impact) with lifecycle/status fields rather than a
static "PQC = yes/no" flag:

* ML-KEM-512/768/1024  — FIPS 203 (finalized Aug 2024)        STANDARDIZED
* ML-DSA-44/65/87      — FIPS 204 (finalized Aug 2024)        STANDARDIZED
* SLH-DSA-128S/-192S/-256S — FIPS 205 (finalized Aug 2024)    STANDARDIZED
* HQC-128/192/256      — selected for standardization (2025)  SELECTED_FOR_STANDARDIZATION
* Kyber / Dilithium / SPHINCS+ — pre-standardization names    LEGACY aliases

Every entry also carries its CycloneDX cryptography-registry OID (§35) so the
live CBOM speaks the ecosystem's representation, not a ZELNX-only one.
"""

from __future__ import annotations

from typing import Any, Optional

from universal_crypto.models import (
    LifecycleStatus,
    QuantumStatus,
    RegistryEntry,
)

try:  # the shared registry is authoritative for canonical names / key sizes
    from shared_models.algorithm_registry import catalog as _shared_catalog
except Exception:  # pragma: no cover — engine works standalone in unit tests
    _shared_catalog = None

#: CycloneDX cryptography registry OIDs (family/variant identifiers).
OID = {
    "AES": "1.2.840.113549.3.7", "AES-GCM": "2.16.840.1.101.3.4.1.6",
    "AES-CBC": "2.16.840.1.101.3.4.1.2", "AES-ECB": "2.16.840.1.101.3.4.1.1",
    "AES-CTR": "2.16.840.1.101.3.4.1.7", "3DES": "1.2.840.113549.3.7",
    "DES": "1.3.14.3.2.7", "RC4": "1.2.840.113549.3.4",
    "ChaCha20": "1.3.6.1.4.1.11591.15.1", "ChaCha20-Poly1305": "1.3.6.1.4.1.11591.15.1",
    "SHA-1": "1.3.14.3.2.26", "SHA-224": "2.16.840.1.101.3.4.2.4",
    "SHA-256": "2.16.840.1.101.3.4.2.1", "SHA-384": "2.16.840.1.101.3.4.2.2",
    "SHA-512": "2.16.840.1.101.3.4.2.3", "SHA3-256": "2.16.840.1.101.3.4.2.8",
    "SHA3-512": "2.16.840.1.101.3.4.2.10", "SHAKE128": "2.16.840.1.101.3.4.2.11",
    "SHAKE256": "2.16.840.1.101.3.4.2.12", "MD5": "1.2.840.113549.2.5",
    "MD4": "1.2.840.113549.2.4", "RIPEMD160": "1.3.36.3.2.2",
    "BLAKE2b": "1.3.6.1.4.1.1722.12.2.1.16", "BLAKE2s": "1.3.6.1.4.1.1722.12.2.2.20",
    "BLAKE3": "1.3.6.1.4.1.1722.12.2.4.1", "RSA": "1.2.840.113549.1.1.1",
    "RSA-PSS": "1.2.840.113549.1.1.10", "RSA-OAEP": "1.2.840.113549.1.1.7",
    "DH": "1.2.840.113549.1.3.1", "ECDH": "1.3.132.1.12",
    "DSA": "1.2.840.10040.4.1", "ECDSA": "1.2.840.10045.4",
    "Ed25519": "1.3.101.112", "Ed448": "1.3.101.113",
    "X25519": "1.3.101.110", "X448": "1.3.101.111",
    "ML-KEM-768": "2.16.840.1.101.3.4.4.1", "ML-KEM-1024": "2.16.840.1.101.3.4.4.2",
    "ML-DSA-65": "2.16.840.1.101.3.4.3.17", "SLH-DSA-128S": "2.16.840.1.101.3.4.3.24",
    "HMAC-SHA256": "1.2.840.113549.2.9", "PBKDF2": "1.2.840.113549.2.7",
    "HKDF": "1.3.6.1.4.1.11129.2.1.4", "P-256": "1.2.840.10045.3.1.7",
    "P-384": "1.3.132.0.34", "P-521": "1.3.132.0.35",
    "TLS": "1.3.6.1.4.1.311.42.1.2", "SSH": "1.3.6.1.4.1.311.42.1.3",
    "IPsec": "1.3.6.1.4.1.311.42.1.4",
}

#: NIST lifecycle per algorithm (overrides/augments the shared verdicts).
_NIST_LIFECYCLE: dict[str, tuple[LifecycleStatus, str]] = {
    "ML-KEM-512": (LifecycleStatus.STANDARDIZED, "FIPS 203"),
    "ML-KEM-768": (LifecycleStatus.STANDARDIZED, "FIPS 203"),
    "ML-KEM-1024": (LifecycleStatus.STANDARDIZED, "FIPS 203"),
    "ML-DSA-44": (LifecycleStatus.STANDARDIZED, "FIPS 204"),
    "ML-DSA-65": (LifecycleStatus.STANDARDIZED, "FIPS 204"),
    "ML-DSA-87": (LifecycleStatus.STANDARDIZED, "FIPS 204"),
    "SLH-DSA-128S": (LifecycleStatus.STANDARDIZED, "FIPS 205"),
    "SLH-DSA-192S": (LifecycleStatus.STANDARDIZED, "FIPS 205"),
    "SLH-DSA-256S": (LifecycleStatus.STANDARDIZED, "FIPS 205"),
    "HQC-128": (LifecycleStatus.SELECTED_FOR_STANDARDIZATION, "NIST selection (2025)"),
    "HQC-192": (LifecycleStatus.SELECTED_FOR_STANDARDIZATION, "NIST selection (2025)"),
    "HQC-256": (LifecycleStatus.SELECTED_FOR_STANDARDIZATION, "NIST selection (2025)"),
    "Kyber": (LifecycleStatus.LEGACY, "pre-standardization name — prefer ML-KEM"),
    "Dilithium": (LifecycleStatus.LEGACY, "pre-standardization name — prefer ML-DSA"),
    "SPHINCS+": (LifecycleStatus.LEGACY, "pre-standardization name — prefer SLH-DSA"),
    "MD5": (LifecycleStatus.DEPRECATED, "collision-broken; prohibited by most policies"),
    "MD4": (LifecycleStatus.DEPRECATED, "broken"),
    "SHA-1": (LifecycleStatus.DEPRECATED, "NIST deprecated since 2011 (SP 800-131A)"),
    "DES": (LifecycleStatus.DEPRECATED, "56-bit key space"),
    "3DES": (LifecycleStatus.DEPRECATED, "SP 800-131A: 3TDEA disallowed after 2023"),
    "RC4": (LifecycleStatus.DEPRECATED, "broken; prohibited (RFC 7465)"),
    "Blowfish": (LifecycleStatus.LEGACY, "64-bit block"),
    "Twofish": (LifecycleStatus.LEGACY, "not standardized by NIST"),
    "SEED": (LifecycleStatus.LEGACY, "Korean national standard"),
    "Camellia": (LifecycleStatus.STANDARDIZED, "ISO/IEC 18033-3"),
    "ARIA": (LifecycleStatus.STANDARDIZED, "Korean national standard"),
    "DSA": (LifecycleStatus.LEGACY, "SP 800-131A restricts; ECDSA preferred"),
    "RIPEMD160": (LifecycleStatus.LEGACY, "not FIPS-approved"),
    "BLAKE3": (LifecycleStatus.CANDIDATE, "not yet standardized"),
    "BLAKE2b": (LifecycleStatus.STANDARDIZED, "RFC 7693"),
    "BLAKE2s": (LifecycleStatus.STANDARDIZED, "RFC 7693"),
}

#: quantum status per family/algorithm (NIST IR 8547: RSA/ECC/DH threatened
#: by cryptographically relevant quantum computers; AES/SHA only halved).
_QUANTUM: dict[str, QuantumStatus] = {
    "RSA": QuantumStatus.QUANTUM_VULNERABLE,
    "DH": QuantumStatus.QUANTUM_VULNERABLE,
    "ECDH": QuantumStatus.QUANTUM_VULNERABLE,
    "ECDSA": QuantumStatus.QUANTUM_VULNERABLE,
    "DSA": QuantumStatus.QUANTUM_VULNERABLE,
    "Ed25519": QuantumStatus.QUANTUM_VULNERABLE,
    "Ed448": QuantumStatus.QUANTUM_VULNERABLE,
    "X25519": QuantumStatus.QUANTUM_VULNERABLE,
    "X448": QuantumStatus.QUANTUM_VULNERABLE,
    "P-256": QuantumStatus.QUANTUM_VULNERABLE,
    "P-384": QuantumStatus.QUANTUM_VULNERABLE,
    "P-521": QuantumStatus.QUANTUM_VULNERABLE,
}

#: additional PQC entries the shared catalog does not carry yet (HQC).
_EXTRA: dict[str, dict[str, Any]] = {
    "HQC-128": {"family": "kem-pqc", "key_size": 3626, "parameter_kind": "key_bits"},
    "HQC-192": {"family": "kem-pqc", "key_size": 7242, "parameter_kind": "key_bits"},
    "HQC-256": {"family": "kem-pqc", "key_size": 14434, "parameter_kind": "key_bits"},
}

#: variant expansion for composite names (RSA-PSS, AES-GCM, Ed25519, ...)
_VARIANT_MAP: dict[str, tuple[str, ...]] = {
    "RSA": ("RSA-PKCS1", "RSA-PSS", "RSA-OAEP"),
    "AES": ("AES-ECB", "AES-CBC", "AES-CTR", "AES-GCM", "AES-CCM", "AES-GCM-SIV"),
    "SHA-3": ("SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "SHAKE128", "SHAKE256"),
    "BLAKE2": ("BLAKE2b", "BLAKE2s"),
    "EdDSA": ("Ed25519", "Ed448"),
    "ECDH": ("ECDH-P-256", "ECDH-P-384", "ECDH-P-521", "X25519", "X448"),
    "ML-KEM": ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"),
    "ML-DSA": ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87"),
    "SLH-DSA": ("SLH-DSA-128S", "SLH-DSA-192S", "SLH-DSA-256S"),
    "HQC": ("HQC-128", "HQC-192", "HQC-256"),
}

_FAMILY_QUANTUM = {
    "kem-pqc": QuantumStatus.QUANTUM_SAFE,
    "signature-pqc": QuantumStatus.QUANTUM_SAFE,
    "block-cipher": QuantumStatus.QUANTUM_SAFE,   # Grover halves, sizes chosen accordingly
    "stream-cipher": QuantumStatus.QUANTUM_SAFE,
    "aead": QuantumStatus.QUANTUM_SAFE,
    "hash": QuantumStatus.QUANTUM_SAFE,
    "mac": QuantumStatus.QUANTUM_SAFE,
    "kdf": QuantumStatus.QUANTUM_SAFE,
    "xof": QuantumStatus.QUANTUM_SAFE,
    "rng": QuantumStatus.QUANTUM_SAFE,
    # asymmetric families — Shor breaks them (NIST IR 8547)
    "pke": QuantumStatus.QUANTUM_VULNERABLE,
    "signature": QuantumStatus.QUANTUM_VULNERABLE,
    "key-agree": QuantumStatus.QUANTUM_VULNERABLE,
    "ec-curve": QuantumStatus.QUANTUM_VULNERABLE,
}

# curves known to the engine (with OIDs)
CURVES = ("P-256", "P-384", "P-521", "X25519", "X448", "secp256k1", "Curve25519", "Curve448", "BrainpoolP256r1", "BrainpoolP384r1")


def _shared_entry(name: str) -> Optional[dict[str, Any]]:
    if _shared_catalog is None:
        return None
    for entry in _shared_catalog():
        if entry.get("algorithm", "").lower() == name.lower():
            return entry
    return None


def registry_entry(name: str) -> RegistryEntry:
    """Canonical RegistryEntry for any algorithm name (parse-tolerant)."""
    canonical = name.strip()
    shared = _shared_entry(canonical)
    if shared is None and "keccak" not in canonical.lower():
        # tolerate case/separator differences via the shared parser when possible
        # (keccak-256 is NOT SHA3-256 — different padding; keep the raw name)
        try:
            from shared_models.algorithm_registry import parse_algorithm
            parsed = parse_algorithm(canonical)
            canonical = parsed.canonical
        except Exception:
            pass
    shared = _shared_entry(canonical) or {}

    family = str(shared.get("family") or "algorithm")
    key_sizes: tuple[int, ...] = ()
    if shared.get("allowed_key_sizes"):
        key_sizes = tuple(int(x) for x in shared["allowed_key_sizes"])
    elif shared.get("key_size"):
        key_sizes = (int(shared["key_size"]),)

    # engine-only extras (HQC) override family/key sizes BEFORE status math
    extra = _EXTRA.get(canonical, {})
    if extra.get("key_size"):
        key_sizes = (int(extra["key_size"]),)
        family = str(extra["family"])

    lifecycle, standard = _NIST_LIFECYCLE.get(canonical, (LifecycleStatus.STANDARDIZED, ""))
    if not standard and canonical in ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"):
        standard = "FIPS 203"
    quantum = _QUANTUM.get(canonical)
    if quantum is None:
        # the shared registry's verdict is authoritative when present
        impact_shared = str(shared.get("quantum_impact") or "")
        if impact_shared == "shor":
            quantum = QuantumStatus.QUANTUM_VULNERABLE
        elif impact_shared == "grover":
            quantum = QuantumStatus.QUANTUM_SAFE
        else:
            quantum = _FAMILY_QUANTUM.get(family, QuantumStatus.PQC_UNKNOWN)
    impact = ""
    if quantum == QuantumStatus.QUANTUM_VULNERABLE:
        impact = "shor"
    elif family in ("block-cipher", "stream-cipher", "aead", "hash", "mac", "kdf"):
        impact = "grover"

    return RegistryEntry(
        algorithm=canonical,
        family=family,
        kind="algorithm",
        nist_lifecycle=lifecycle,
        standard_reference=standard or str(shared.get("notes") or ""),
        quantum_status=quantum,
        quantum_impact=impact,
        key_sizes=key_sizes,
        curves=tuple(c for c in CURVES if c.lower() in canonical.lower()),
        variants=_VARIANT_MAP.get(canonical, ()),
        oid=OID.get(canonical, ""),
        notes=str(shared.get("notes") or ""),
    )


def catalog() -> list[RegistryEntry]:
    """Full §2 registry: shared catalog + HQC + curves + protocol assets."""
    names = set()
    if _shared_catalog is not None:
        for entry in _shared_catalog():
            names.add(entry["algorithm"])
    for extra in _EXTRA:
        names.add(extra)
    for curve in CURVES:
        names.add(curve)
    names.update(("TLS", "SSH", "IPsec", "QUIC"))
    out = [registry_entry(n) for n in sorted(names)]
    return out


def find(name: str) -> Optional[RegistryEntry]:
    try:
        return registry_entry(name)
    except Exception:
        return None


def quantum_status(algorithm: str) -> QuantumStatus:
    entry = find(algorithm)
    if entry is None:
        return QuantumStatus.PQC_UNKNOWN
    return entry.quantum_status


def lifecycle_status(algorithm: str) -> LifecycleStatus:
    entry = find(algorithm)
    if entry is None:
        return LifecycleStatus.CANDIDATE
    return entry.nist_lifecycle


def oid_for(algorithm: str) -> str:
    entry = find(algorithm)
    return entry.oid if entry else ""
