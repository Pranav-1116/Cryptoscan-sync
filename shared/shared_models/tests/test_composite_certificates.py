"""Composite / hybrid certificate detection (advanced/59, round 32)."""

from __future__ import annotations

from shared_models.composite_certificates import (
    COMPOSITE_OID_ARCS,
    composite_block,
    detect_composite,
)


def test_detects_composite_signature_by_oid_arc():
    result = detect_composite(
        signature_algorithm_oid="2.16.840.1.114027.80.7",
        signature_algorithm="id-ML-DSA65-RSA3072-PSS-SHA512",
    )
    assert result is not None
    assert result["scheme"] == "composite-signature"
    assert result["match"] == "oid-arc"
    # components parsed from the name, PQ + classical both present
    assert any("ML-DSA-65" in c for c in result["components"])
    assert any("RSA" in c for c in result["components"])


def test_detects_composite_kem_by_oid_arc():
    result = detect_composite(signature_algorithm_oid="2.16.840.1.114027.82.1")
    assert result is not None
    assert result["scheme"] == "composite-kem"


def test_detects_composite_by_name_without_oid():
    cases = [
        "id-ML-DSA65-RSA2048-PSS-SHA256",
        "ML-KEM-768+ECDH-P384",
        "mldsa65_rsa2048_sha256",
        "Composite ML-DSA-44 + ECDSA-P256",
    ]
    for name in cases:
        result = detect_composite(signature_algorithm=name)
        assert result is not None, name
        assert result["match"] == "name"
        assert len(result["components"]) >= 2, name
        assert result["scheme"] in ("composite-signature", "composite-kem")
    assert detect_composite(signature_algorithm="ML-KEM-768+ECDH-P384")["scheme"] == "composite-kem"


def test_ordinary_algorithms_are_not_composite():
    for name in ("RSA", "RSA-2048", "ECDSA-P256-SHA256", "sha256WithRSAEncryption",
                 "ML-DSA-65", "ML-KEM-768", "Ed25519", "ECDSA-SHA384"):
        assert detect_composite(signature_algorithm=name) is None, name
    # a lone PQ name in the public-key slot is still one algorithm
    assert detect_composite(public_key_algorithm="ML-DSA-87") is None


def test_unknown_oid_is_honest_absence():
    # not on a composite arc, no name to match — no guess
    assert detect_composite(signature_algorithm_oid="1.2.840.113549.1.1.11") is None
    assert detect_composite() is None
    # arc prefix must match fully — a nearby arc does not trip it
    assert detect_composite(signature_algorithm_oid="2.16.840.1.114027.90.1") is None


def test_composite_block_reads_payload_keys():
    payload = {
        "signature_algorithm": "id-ML-DSA44-ECDSA-P256-SHA256",
        "public_key_algorithm": "ECDSA",
    }
    block = composite_block(payload)
    assert block is not None and block["match"] == "name"
    assert composite_block({"public_key_algorithm": "RSA"}) is None
    assert composite_block(None) is None


def test_registry_arcs_are_registered_prefixes():
    assert all(arc.startswith("2.16.840.1.114027.8") for arc in COMPOSITE_OID_ARCS)
    assert set(COMPOSITE_OID_ARCS.values()) <= {"composite-signature", "composite-kem"}
