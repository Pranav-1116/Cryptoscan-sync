"""§2 algorithm registry: NIST lifecycle/status, quantum status, OIDs."""

from __future__ import annotations

from universal_crypto.models import LifecycleStatus, QuantumStatus
from universal_crypto.registry import (
    OID,
    catalog,
    find,
    lifecycle_status,
    oid_for,
    quantum_status,
    registry_entry,
)


def test_pqc_standards_have_lifecycle_status_not_boolean():
    # ML-KEM / ML-DSA / SLH-DSA are finalized standards (FIPS 203/204/205)
    assert lifecycle_status("ML-KEM-768") == LifecycleStatus.STANDARDIZED
    assert lifecycle_status("ML-DSA-65") == LifecycleStatus.STANDARDIZED
    assert lifecycle_status("SLH-DSA-128S") == LifecycleStatus.STANDARDIZED
    assert registry_entry("ML-KEM-768").standard_reference == "FIPS 203"
    assert registry_entry("ML-DSA-65").standard_reference == "FIPS 204"
    # HQC was selected for standardization (2025) — NOT yet a final standard
    assert lifecycle_status("HQC-192") == LifecycleStatus.SELECTED_FOR_STANDARDIZATION
    assert registry_entry("HQC-192").quantum_status == QuantumStatus.QUANTUM_SAFE


def test_pre_standardization_names_are_legacy_aliases():
    assert lifecycle_status("Kyber") == LifecycleStatus.LEGACY
    assert lifecycle_status("Dilithium") == LifecycleStatus.LEGACY


def test_quantum_status_of_classical_families():
    assert quantum_status("RSA") == QuantumStatus.QUANTUM_VULNERABLE
    assert quantum_status("ECDSA") == QuantumStatus.QUANTUM_VULNERABLE
    assert quantum_status("ECDH") == QuantumStatus.QUANTUM_VULNERABLE
    assert quantum_status("Ed25519") == QuantumStatus.QUANTUM_VULNERABLE
    assert quantum_status("AES") == QuantumStatus.QUANTUM_SAFE
    assert quantum_status("SHA-256") == QuantumStatus.QUANTUM_SAFE


def test_registry_covers_spec_algorithm_list():
    entry = find("ChaCha20-Poly1305")
    assert entry is not None and entry.family == "aead"
    for name in ("AES", "3DES", "DES", "Camellia", "ARIA", "SEED", "Blowfish",
                 "Twofish", "RC4", "SHA-1", "SHA-256", "SHA-3", "SHAKE128",
                 "MD5", "RIPEMD160", "BLAKE2", "BLAKE3", "RSA", "DH", "DSA",
                 "Ed448", "ML-KEM-512", "ML-KEM-1024", "ML-DSA-44", "ML-DSA-87",
                 "SLH-DSA-192S", "SLH-DSA-256S", "HQC-128", "HQC-256"):
        assert find(name) is not None, name


def test_catalog_has_curves_and_protocols():
    names = {e.algorithm for e in catalog()}
    assert {"P-256", "P-384", "P-521", "X25519", "TLS", "SSH", "IPsec", "QUIC"} <= names


def test_cyclonedx_oids_are_present():
    for algorithm in ("AES-GCM", "RSA-PSS", "Ed25519", "SHA-256", "ML-KEM-768",
                      "ML-DSA-65", "SLH-DSA-128S", "X25519", "P-256"):
        assert oid_for(algorithm), algorithm
    assert OID["ML-KEM-768"].startswith("2.16.840.1.101.3.4.4")  # NIST PQC arc
