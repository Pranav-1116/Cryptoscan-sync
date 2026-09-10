"""§19 PQC readiness engine.

Per crypto asset: CLASSICAL / QUANTUM_VULNERABLE / QUANTUM_SAFE / HYBRID /
PQC_READY / PQC_UNKNOWN, then the migration pipeline:

    Current Algorithm
      → Replacement Candidates
      → Protocol Compatibility
      → Library Support
      → Hardware Support
      → Vendor Support
      → Application Compatibility
      → Migration Readiness
"""

from __future__ import annotations

from typing import Any

from universal_crypto.models import QuantumStatus
from universal_crypto.registry import find as _registry_find

#: current algorithm → replacement candidates (deterministic catalog)
REPLACEMENT_CANDIDATES: dict[str, list[str]] = {
    "RSA": ["ML-KEM-768", "ML-DSA-65", "SLH-DSA-128S", "Hybrid: X25519+ML-KEM-768"],
    "RSA-PSS": ["ML-DSA-65", "SLH-DSA-128S", "Hybrid: ECDSA+ML-DSA-65"],
    "RSA-OAEP": ["ML-KEM-768", "Hybrid: RSA-OAEP+ML-KEM-768"],
    "RSA-PKCS1": ["ML-DSA-65", "SLH-DSA-128S", "Hybrid: ECDSA+ML-DSA-65"],
    "DH": ["ML-KEM-768", "X25519"],
    "ECDH": ["ML-KEM-768", "X25519"],
    "ECDSA": ["ML-DSA-65", "SLH-DSA-128S"],
    "Ed25519": ["ML-DSA-65", "SLH-DSA-128S"],
    "Ed448": ["ML-DSA-87", "SLH-DSA-256S"],
    "DSA": ["ML-DSA-65", "ECDSA"],
    "X25519": ["ML-KEM-768", "Hybrid: X25519+ML-KEM-768"],
    "P-256": ["ML-KEM-768", "ML-DSA-65"],
    "P-384": ["ML-KEM-1024", "ML-DSA-87"],
    "P-521": ["ML-KEM-1024", "ML-DSA-87"],
    "AES": ["AES-256", "AES-256-GCM"],
    "SHA-1": ["SHA-256", "SHA-384"],
    "MD5": ["SHA-256", "BLAKE2b"],
}

#: protocol → which PQC algorithms it can carry (deterministic catalog)
PROTOCOL_COMPATIBILITY: dict[str, list[str]] = {
    "TLS": ["ML-KEM-768", "ML-KEM-1024", "ML-DSA-65", "ML-DSA-87",
            "SLH-DSA-128S", "X25519"],
    "TLS 1.3": ["ML-KEM-768", "ML-KEM-1024", "ML-DSA-65", "ML-DSA-87",
                "SLH-DSA-128S", "X25519"],
    "SSH": ["ML-KEM-768", "X25519", "ML-DSA-65", "SLH-DSA-128S"],
    "IPsec": ["ML-KEM-768", "X25519", "ML-DSA-65"],
    "QUIC": ["ML-KEM-768", "ML-DSA-65"],
    "CMS": ["ML-DSA-65", "SLH-DSA-128S"],
    "X.509": ["ML-DSA-65", "SLH-DSA-128S", "ML-KEM-768"],
    "JOSE": ["ML-DSA-65", "SLH-DSA-128S"],
    "PKCS#11": ["ML-KEM-768", "ML-DSA-65", "SLH-DSA-128S"],
    "": [],
}

#: library → PQC algorithms supported (overlaps §6 exposed catalog)
LIBRARY_PQC_SUPPORT: dict[str, list[str]] = {
    "OpenSSL": ["ML-KEM-768", "ML-KEM-1024", "ML-DSA-65", "ML-DSA-87"],
    "BoringSSL": ["ML-KEM-768"],
    "libsodium": ["ML-KEM-768"],
    "Botan": ["ML-KEM-768", "ML-DSA-65", "HQC-192"],
    "wolfSSL": ["ML-KEM-768", "ML-DSA-65"],
    "mbedTLS": [],
    "BouncyCastle": ["ML-KEM-768", "ML-DSA-65", "HQC-192"],
    "JCA-JCE": [],
    ".NET cryptography": [],
    "Go crypto/*": [],
    "RustCrypto": ["ML-KEM-768", "ML-DSA-65"],
    "WebCrypto": [],
    "Node crypto": [],
    "CryptoKit": [],
}

#: hardware → PQC capabilities (support ≠ usage, §27)
HARDWARE_PQC_SUPPORT: dict[str, list[str]] = {
    "HSM": ["ML-KEM-768", "ML-DSA-65", "SLH-DSA-128S"],
    "TPM 2.0": [],
    "SmartCard": [],
    "SecureEnclave": [],
    "Cloud KMS": ["ML-KEM-768", "ML-DSA-65"],
}


class PqcReadinessEngine:
    """§19 readiness per asset + the full migration-readiness pipeline."""

    def readiness_status(
        self,
        *,
        algorithm: str,
        usage: bool,
        capability: bool = False,
        replacement_available: bool = True,
    ) -> QuantumStatus:
        """The §19 status of one asset."""
        entry = _registry_find(algorithm)
        if entry is not None and entry.quantum_status in (
            QuantumStatus.QUANTUM_SAFE, QuantumStatus.PQC_READY):
            # already quantum-safe: in use (or capability present) = PQC-ready
            return QuantumStatus.PQC_READY if (usage or capability) \
                else QuantumStatus.QUANTUM_SAFE
        if algorithm.startswith("Hybrid:"):
            return QuantumStatus.HYBRID
        if entry is not None and entry.quantum_status == QuantumStatus.PQC_UNKNOWN:
            return QuantumStatus.PQC_UNKNOWN
        if not replacement_available:
            return QuantumStatus.PQC_UNKNOWN
        if capability:
            return QuantumStatus.HYBRID  # capability present, usage pending
        return QuantumStatus.QUANTUM_VULNERABLE

    def migration_readiness(
        self,
        *,
        algorithm: str,
        protocol: str = "",
        library: str = "",
        hardware: str = "",
        vendor_support: bool = True,
        application_compatible: bool = True,
        usage: bool = True,
    ) -> dict[str, Any]:
        """Full §19 pipeline for one asset."""
        candidates = REPLACEMENT_CANDIDATES.get(algorithm, [])
        if not candidates and algorithm.startswith("Hybrid:"):
            candidates = [algorithm]
        statuses = []
        for candidate in candidates:
            if candidate.startswith("Hybrid:"):
                statuses.append({"candidate": candidate, "compatible": True,
                                 "fully_compatible": True,
                                 "protocol_compatible": True,
                                 "library_supported": True,
                                 "hardware_supported": True,
                                 "vendor_supported": vendor_support,
                                 "application_compatible": application_compatible})
                continue
            protocol_ok = candidate in PROTOCOL_COMPATIBILITY.get(protocol, [])
            library_ok = candidate in LIBRARY_PQC_SUPPORT.get(library, [])
            hardware_ok = candidate in HARDWARE_PQC_SUPPORT.get(hardware, [])
            statuses.append({
                "candidate": candidate,
                "protocol_compatible": protocol_ok,
                "library_supported": library_ok,
                "hardware_supported": hardware_ok,
                "vendor_supported": vendor_support,
                "application_compatible": application_compatible,
                "fully_compatible": protocol_ok and library_ok and (
                    hardware_ok or not hardware) and vendor_support
                    and application_compatible,
            })
        current_status = self.readiness_status(
            algorithm=algorithm, usage=usage, capability=hardware != "")
        ready = any(s["fully_compatible"] for s in statuses) if statuses else False
        return {
            "algorithm": algorithm,
            "current_status": current_status.value,
            "replacement_candidates": candidates,
            "candidate_analysis": statuses,
            "migration_readiness": "READY" if ready else (
                "PLANNED" if statuses else "NO_PATH"),
        }
