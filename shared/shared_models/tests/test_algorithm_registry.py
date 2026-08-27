"""Algorithm registry tests — every algorithm with its key size."""

from __future__ import annotations

import pytest

from shared_models.algorithm_registry import (
    ALLOWED,
    DEPRECATED,
    DISALLOWED,
    RESTRICTED,
    UNKNOWN,
    catalog,
    infer_key_size,
    parse_algorithm,
)


@pytest.mark.parametrize(
    ("raw", "algorithm", "bits", "status"),
    [
        # the user's headline examples
        ("AES-256", "AES", 256, ALLOWED),
        ("DES", "DES", 56, DISALLOWED),
        ("SHA-256", "SHA-256", 256, ALLOWED),
        # spacing / separator / case tolerance
        ("aes_128_gcm", "AES-GCM", 128, ALLOWED),
        ("AES/GCM/NoPadding", "AES-GCM", None, ALLOWED),
        ("aes256-ctr", "AES", 256, ALLOWED),
        ("AES-256-XTS", "AES-XTS", 256, RESTRICTED),
        # DES family
        ("DESede", "3DES", 168, DEPRECATED),
        ("des-ede3-cbc", "3DES", 168, DEPRECATED),
        ("3DES", "3DES", 168, DEPRECATED),
        # hashes
        ("SHA1", "SHA-1", 160, DEPRECATED),
        ("sha3-512", "SHA3-512", 512, ALLOWED),
        ("MD5", "MD5", 128, DISALLOWED),
        ("SHA512", "SHA-512", 512, ALLOWED),
        ("SHA-512/256", "SHA-512/256", 256, ALLOWED),
        # RSA with sizes
        ("RSA-2048", "RSA", 2048, ALLOWED),
        ("RSA2048", "RSA", 2048, ALLOWED),
        ("RSA-1024", "RSA", 1024, DISALLOWED),
        ("RSA", "RSA", None, ALLOWED),
        # ECC
        ("ECDSA-P256", "ECDSA", 256, ALLOWED),
        ("P-384", "P-384", 384, ALLOWED),
        ("prime256v1", "P-256", 256, ALLOWED),
        ("Ed25519", "Ed25519", 256, ALLOWED),
        ("X25519", "X25519", 256, ALLOWED),
        # stream / other
        ("RC4", "RC4", None, DISALLOWED),
        ("chacha20-poly1305@openssh.com", "ChaCha20-Poly1305", 256, ALLOWED),
        ("Blowfish", "Blowfish", None, RESTRICTED),
        # MACs
        ("HmacSHA256", "HMAC-SHA-256", 256, ALLOWED),
        ("HMAC-MD5", "HMAC-MD5", 128, DISALLOWED),
        ("hmac-sha2-512", "HMAC-SHA-512", 512, ALLOWED),
        # JOSE
        ("RS256", "RSA", 2048, ALLOWED),
        ("ES384", "ECDSA", 384, ALLOWED),
        ("HS256", "HMAC-SHA-256", 256, ALLOWED),
        ("A256GCM", "AES-GCM", 256, ALLOWED),
        ("RSA1_5", "RSA-PKCS1v1.5", None, DISALLOWED),
        ("RSA-OAEP", "RSA-OAEP", 2048, ALLOWED),
        # signature combos
        ("SHA256withRSA", "RSA", 2048, ALLOWED),
        # KDFs
        ("PBKDF2WithHmacSHA256", "PBKDF2", None, RESTRICTED),
        ("Argon2", "Argon2", None, ALLOWED),
        # SSH
        ("ssh-ed25519", "Ed25519", 256, ALLOWED),
        ("ssh-rsa", "ssh-rsa", None, DEPRECATED),
        ("diffie-hellman-group14-sha256", "DH group-14", 2048, RESTRICTED),
        ("diffie-hellman-group1-sha1", "DH group-1", 1024, DISALLOWED),
        # PQC
        ("ML-KEM-768", "ML-KEM-768", 1184, ALLOWED),
        ("ML-DSA-65", "ML-DSA-65", 1952, ALLOWED),
    ],
)
def test_parse_algorithm_key_and_status(raw, algorithm, bits, status):
    info = parse_algorithm(raw)
    assert info.canonical == algorithm, raw
    assert info.key_size == bits, raw
    assert info.status == status, raw


def test_unknown_algorithm_degrades_not_silences():
    info = parse_algorithm("SCRATCHPAD-9000")
    assert info.status == UNKNOWN
    assert info.recognized is False
    assert info.notes


def test_embedded_size_survives_unknown_family():
    assert parse_algorithm("FOO-256").key_size == 256


def test_tls_suite_breakdown():
    info = parse_algorithm("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
    assert info.family == "tls-suite"
    assert info.status == ALLOWED
    assert info.key_size == 128
    roles = {c["role"] for c in info.components}
    assert "key_exchange" in roles
    assert "bulk_cipher" in roles
    assert "mac" in roles
    assert info.quantum_impact == "shor"  # ECDHE/RSA components


def test_tls_weak_suites_flagged():
    assert parse_algorithm("TLS_RSA_WITH_RC4_128_MD5").status == DISALLOWED
    assert parse_algorithm("TLS_RSA_WITH_AES_128_CBC_SHA").status in {DEPRECATED, RESTRICTED}
    assert parse_algorithm("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA").status in {DISALLOWED, RESTRICTED, DEPRECATED}


def test_ecb_mode_flagged():
    assert parse_algorithm("AES/ECB/PKCS5Padding").status == DISALLOWED
    assert parse_algorithm("AES/ECB/NoPadding").mode == "ECB"


def test_quantum_impact():
    assert parse_algorithm("RSA-2048").quantum_impact == "shor"
    assert parse_algorithm("AES-256").quantum_impact == "grover"
    assert parse_algorithm("ML-KEM-768").quantum_impact is None
    assert parse_algorithm("RSA-2048").to_dict()["quantum_vulnerable"] is True
    assert parse_algorithm("AES-256").to_dict()["quantum_vulnerable"] is False


def test_infer_key_size_helper():
    assert infer_key_size("AES-256") == 256
    assert infer_key_size("3DES") == 168
    assert infer_key_size(None) is None
    assert infer_key_size("TLS") is None


def test_catalog_is_complete_and_shaped():
    entries = catalog()
    names = [e["algorithm"] for e in entries]
    assert len(entries) > 50
    for wanted in ("AES", "DES", "3DES", "SHA-256", "MD5", "RSA", "ECDSA", "Ed25519", "ML-KEM-768"):
        assert wanted in names
    des = next(e for e in entries if e["algorithm"] == "DES")
    assert des["key_size"] == 56
    assert des["status"] == DISALLOWED


def test_parse_empty_is_safe():
    info = parse_algorithm("")
    assert info.recognized is False
    assert parse_algorithm("   ").status == UNKNOWN
