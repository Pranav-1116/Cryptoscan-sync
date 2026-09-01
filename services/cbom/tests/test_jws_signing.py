"""RFC 7515 JWS CBOM signing — RS256 / ES256 / HS256."""

from __future__ import annotations

import pytest

from cbom.generator import CbomGenerator
from cbom.signing.jws_signer import (
    SUPPORTED_ALGS,
    b64url_decode,
    sign_cbom_jws,
    sign_compact,
    verify_cbom_jws,
    verify_compact,
)

pytest.importorskip("cryptography")

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa


def _rsa_keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return priv, pub


def _ec_keypair():
    key = ec.generate_private_key(ec.SECP256R1())
    priv = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return priv, pub


def _sample_bom() -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:11111111-2222-3333-4444-555555555555",
        "components": [{"type": "cryptographic-asset", "name": "RSA", "properties": []}],
        "metadata": {"properties": [{"name": "cryptoscan:scan", "value": "s1"}]},
    }


def test_rs256_roundtrip():
    priv, pub = _rsa_keypair()
    bom = _sample_bom()
    signed = sign_cbom_jws(bom, priv, alg="RS256", key_id="cbom-rsa-1")
    props = {p["name"]: p["value"] for p in signed["metadata"]["properties"]}
    assert props["cryptoscan:signatureAlg"] == "JWS-RS256"
    assert props["cryptoscan:jws"].count(".") == 2
    # kid is embedded
    header = b64url_decode(props["cryptoscan:jws"].split(".")[0])
    assert b"cbom-rsa-1" in header
    ok, err = verify_cbom_jws(signed, pub)
    assert ok, err
    # generator-level API
    ok2, err2 = CbomGenerator().verify_jws(signed, pub)
    assert ok2, err2


def test_es256_roundtrip():
    priv, pub = _ec_keypair()
    bom = _sample_bom()
    signed = CbomGenerator().sign_jws(bom, priv, alg="ES256", key_id="cbom-ec-1")
    ok, err = verify_cbom_jws(signed, pub)
    assert ok, err


def test_hs256_roundtrip():
    bom = _sample_bom()
    signed = sign_cbom_jws(bom, "shared-secret", alg="HS256", key_id="cbom-hs-1")
    ok, err = verify_cbom_jws(signed, "shared-secret")
    assert ok, err


def test_tamper_detected():
    priv, pub = _rsa_keypair()
    signed = sign_cbom_jws(_sample_bom(), priv, alg="RS256")
    signed["components"][0]["name"] = "AES"  # tamper after signing
    ok, err = verify_cbom_jws(signed, pub)
    assert not ok
    assert "payload" in err or "signature" in err


def test_wrong_key_rejected():
    priv, pub = _rsa_keypair()
    other_priv, _ = _rsa_keypair()
    signed = sign_cbom_jws(_sample_bom(), priv, alg="RS256")
    ok, _ = verify_cbom_jws(signed, other_priv)
    assert not ok


def test_compact_verification_is_rfc_verifiable():
    """The compact form must verify as a standalone JWS (payload = canonical body)."""
    priv, pub = _rsa_keypair()
    bom = _sample_bom()
    signed = sign_cbom_jws(bom, priv, alg="RS256", key_id="kid-1")
    jws = {p["name"]: p["value"] for p in signed["metadata"]["properties"]}["cryptoscan:jws"]
    header, payload_b64, _sig = jws.split(".")
    assert b64url_decode(payload_b64) == b'{"bomFormat":"CycloneDX","components":[{"name":"RSA","properties":[],"type":"cryptographic-asset"}],"metadata":{"properties":[{"name":"cryptoscan:scan","value":"s1"}]},"serialNumber":"urn:uuid:11111111-2222-3333-4444-555555555555","specVersion":"1.5"}'
    ok, err = verify_compact(jws, pub)
    assert ok, err


def test_unsupported_alg_rejected():
    with pytest.raises(ValueError):
        sign_compact(b"x", b"secret", "PS256")
    ok, err = verify_compact("a.b.c", b"secret", "PS256")
    assert not ok and "unsupported" in err


def test_all_supported_algs_declared():
    assert SUPPORTED_ALGS == {"RS256", "ES256", "HS256"}
