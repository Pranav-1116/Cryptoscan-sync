"""Classical and NIST post-quantum security levels for CBOM algorithmProperties."""

from __future__ import annotations

from typing import Any

CLASSICAL_BITS = {
    "AES": None,  # key size
    "AES-128": 128,
    "AES-192": 192,
    "AES-256": 256,
    "SHA-1": 80,
    "SHA-256": 256,
    "SHA-384": 384,
    "SHA-512": 512,
    "SHA3-256": 256,
    "MD5": 64,
    "DES": 56,
    "3DES": 112,
    "RC4": 40,
    "RSA": None,
    "ECDSA": 128,
    "DSA": 112,
    "ECDH": 128,
    "CHACHA20": 256,
    "CHACHA20-POLY1305": 256,
    "ML-KEM-768": 192,
    "ML-KEM-1024": 256,
    "ML-DSA-65": 192,
    "ML-DSA-87": 256,
}

RSA_CLASSICAL = {1024: 80, 2048: 112, 3072: 128, 4096: 152}

PQC_ALGORITHMS = {
    "ML-KEM-512": 1,
    "ML-KEM-768": 3,
    "ML-KEM-1024": 5,
    "ML-DSA-44": 2,
    "ML-DSA-65": 3,
    "ML-DSA-87": 5,
    "SLH-DSA": 3,
}

QUANTUM_BROKEN = {"RSA", "ECDSA", "DSA", "ECDH", "DH", "ED25519", "X25519"}


def _algo(asset: Any) -> str:
    if isinstance(asset, dict):
        return str(asset.get("algorithm") or "").upper()
    return str(getattr(asset, "algorithm", "") or "").upper()


def _key_size(asset: Any) -> int | None:
    if isinstance(asset, dict):
        value = asset.get("key_size")
    else:
        value = getattr(asset, "key_size", None)
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def calculate_sec_level(asset: Any) -> int | None:
    algorithm = _algo(asset)
    key_size = _key_size(asset)
    if algorithm.startswith("AES") and key_size:
        return key_size
    if algorithm == "RSA" and key_size:
        return RSA_CLASSICAL.get(key_size) or (int(key_size * 0.055) if key_size else None)
    if algorithm in CLASSICAL_BITS and CLASSICAL_BITS[algorithm] is not None:
        return CLASSICAL_BITS[algorithm]
    if algorithm.startswith("AES-") and algorithm.split("-")[-1].isdigit():
        return int(algorithm.split("-")[-1])
    return key_size


def calculate_pq_level(asset: Any) -> int | None:
    algorithm = _algo(asset)
    if algorithm in PQC_ALGORITHMS:
        return PQC_ALGORITHMS[algorithm]
    if algorithm in QUANTUM_BROKEN or algorithm.startswith("RSA") or algorithm.startswith("EC"):
        return 0
    if algorithm.startswith("AES"):
        bits = calculate_sec_level(asset) or 128
        return 3 if bits >= 256 else 1
    if algorithm.startswith("SHA"):
        return 2
    return None


def calculate_security_levels(asset: Any) -> dict[str, int | None]:
    return {
        "classicalSecurityLevel": calculate_sec_level(asset),
        "nistQuantumSecurityLevel": calculate_pq_level(asset),
    }
