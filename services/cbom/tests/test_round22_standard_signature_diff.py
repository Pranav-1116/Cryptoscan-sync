"""Round 22 (report 08 P2#6/P2#7/P2#8): standard signature, compositions,
externalReferences, semantic diff classification."""

from __future__ import annotations

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from cbom.generator import CbomGenerator
from cbom.inventory import semantic_diff, semantic_diff_boms
from cbom.signing.jsf_signer import canonical_json, sign_jsf, verify_jsf


def _record(**overrides):
    base = {
        "id": "a-1",
        "algorithm": "AES",
        "mode": "CBC",
        "padding": None,
        "key_size": 128,
        "file_path": "src/crypto.py",
        "line_number": 10,
        "confidence": "HIGH",
        "normalized_crypto": {"standard_name": "AES"},
    }
    base.update(overrides)
    return base


def _bom(records=None, **kwargs):
    return CbomGenerator().from_records(
        records if records is not None else [_record()], **kwargs
    )


def _ec_pem():
    key = ec.generate_private_key(ec.SECP256R1())
    private = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private, public


def _rsa_pem():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private, public


# --------------------------------------------------------------------- #
# P2#6 — CycloneDX-spec standard enveloped signature (JSF)
# --------------------------------------------------------------------- #

def test_jsf_signature_shape_matches_spec():
    private, public = _ec_pem()
    signed = sign_jsf(_bom(), private, alg="ES256", key_id="k-1")
    sig = signed["signature"]
    assert sig["algorithm"] == "ES256"
    assert sig["keyId"] == "k-1"
    # embedded JWK for the verifier
    assert sig["publicKey"]["kty"] == "EC"
    assert sig["publicKey"]["crv"] == "P-256"
    assert sig["publicKey"]["x"] and sig["publicKey"]["y"]
    # raw IEEE P-1363 r||s = 64 bytes
    value = sig["value"]
    pad = "=" * (-len(value) % 4)
    assert len(base64.urlsafe_b64decode(value + pad)) == 64


def test_jsf_verify_with_trusted_key_and_embedded_jwk():
    private, public = _ec_pem()
    signed = sign_jsf(_bom(), private, alg="ES256")
    ok, error = verify_jsf(signed, public)
    assert ok, error
    # integrity-only: the embedded JWK also verifies
    ok, error = verify_jsf(signed, None)
    assert ok, error


def test_jsf_tamper_detection():
    private, public = _ec_pem()
    signed = sign_jsf(_bom(), private, alg="ES256")
    signed["components"][0]["name"] = "EVIL"
    ok, _error = verify_jsf(signed, public)
    assert not ok


def test_jsf_rs256_and_hs256_roundtrips():
    private, public = _rsa_pem()
    signed = sign_jsf(_bom(), private, alg="RS256")
    ok, error = verify_jsf(signed, public)
    assert ok, error

    shared = "hunter2-but-long-enough"
    signed = sign_jsf(_bom(), shared, alg="HS256", key_id="ops-secret")
    assert signed["signature"]["keyId"] == "ops-secret"
    assert "publicKey" not in signed["signature"]  # secrets are never embedded
    ok, error = verify_jsf(signed, shared)
    assert ok, error
    ok, _ = verify_jsf(signed, "wrong-secret")
    assert not ok
    ok, _ = verify_jsf(signed, None)
    assert not ok  # HS256 without the secret is a hard no


def test_jsf_resign_drops_legacy_jws_property():
    private, public = _ec_pem()
    bom = _bom()
    legacy = CbomGenerator().sign_jws(bom, private, alg="ES256")
    assert any(
        item.get("name") == "cryptoscan:jws"
        for item in (legacy.get("metadata") or {}).get("properties") or []
    )
    resigned = sign_jsf(legacy, private, alg="ES256")
    # the legacy property is stripped from both the output and the signed body
    assert not any(
        item.get("name") == "cryptoscan:jws"
        for item in (resigned.get("metadata") or {}).get("properties") or []
    )
    ok, error = verify_jsf(resigned, public)
    assert ok, error


def test_generator_verify_report_prefers_standard_field():
    gen = CbomGenerator()
    private, _public = _ec_pem()
    signed = gen.sign_standard(_bom(), private, alg="ES256", key_id="k")
    # verify_report takes the standard path (algorithm recorded as ES256)
    report = gen.verify_report(signed, "unused-hmac-secret")
    assert report["ok"], report["error"]
    assert report["algorithm"] == "ES256"
    assert report["key_id"] == "k"
    assert report["checks"][0]["name"] == "standard_signature_field"


def test_canonical_json_is_jcs_compatible_for_bom_data():
    assert canonical_json({"b": 1, "a": "x"}) == b'{"a":"x","b":1}'


# --------------------------------------------------------------------- #
# P2#7 — compositions + externalReferences
# --------------------------------------------------------------------- #

def test_compositions_declares_incomplete_honestly():
    bom = _bom([_record(id="a-1"), _record(id="a-2", mode="GCM")])
    assert bom["compositions"] == [
        {
            "aggregate": "INCOMPLETE",
            "assemblies": ["a-1", "a-2"],
        }
    ]


def test_external_references_provenance_and_component_location():
    bom = _bom([_record()], scan_id="scan-42")
    assert bom["externalReferences"] == [
        {"type": "provenance", "url": "urn:cryptoscan:scan:scan-42"}
    ]
    comp = bom["components"][0]
    assert comp["externalReferences"] == [
        {"type": "other", "url": "file://src/crypto.py"}
    ]
    # no scan_id -> no document-level provenance reference
    assert "externalReferences" not in _bom()


def test_xml_renders_new_fields():
    bom = _bom([_record()], scan_id="scan-7")
    xml = CbomGenerator().to_xml(bom)
    assert '<composition aggregate="INCOMPLETE">' in xml
    assert 'assembly ref="a-1"' in xml
    assert '<reference type="provenance">' in xml
    assert "urn:cryptoscan:scan:scan-7" in xml
    assert '<reference type="other">' in xml
    assert "file://src/crypto.py" in xml


# --------------------------------------------------------------------- #
# P2#8 — semantic diff classification
# --------------------------------------------------------------------- #

def test_semantic_diff_classifies_attribute_changes():
    left = [_record(id="a-1", algorithm="AES", mode="CBC", key_size=128, file_path="f.py", line_number=1)]
    right = [
        # same logical component (AES @ f.py), mode changed
        _record(id="b-1", algorithm="AES", mode="GCM", key_size=128, file_path="f.py", line_number=1),
    ]
    result = semantic_diff(left, right)
    assert result["counts"]["changed"] == 1
    change = result["changed"][0]
    assert change["classifications"] == ["ALGORITHM_CHANGED"]
    assert change["from"]["mode"] == "CBC"
    assert change["to"]["mode"] == "GCM"


def test_semantic_diff_parameter_change_and_line_drift_is_silent():
    left = [
        _record(id="a-1", algorithm="RSA", mode=None, key_size=2048, file_path="k.py", line_number=5),
    ]
    right = [
        # key size changed at the same site...
        _record(id="b-1", algorithm="RSA", mode=None, key_size=4096, file_path="k.py", line_number=99),
    ]
    result = semantic_diff(left, right)
    assert result["counts"]["changed"] == 1
    assert result["changed"][0]["classifications"] == ["PARAMETER_CHANGED"]


def test_semantic_diff_location_move_is_classified():
    left = [
        _record(id="a-1", algorithm="RSA", mode=None, key_size=2048, file_path="old.py", line_number=5),
    ]
    right = [
        # same crypto identity, different file — a move, not add+remove
        _record(id="b-1", algorithm="RSA", mode=None, key_size=2048, file_path="new.py", line_number=1),
    ]
    result = semantic_diff(left, right)
    assert result["counts"] == {"added": 0, "removed": 0, "unchanged": 0, "changed": 1}
    change = result["changed"][0]
    assert change["classifications"] == ["LOCATION_CHANGED"]
    assert change["location"] == "old.py -> new.py"


def test_semantic_diff_same_algorithm_new_site_is_added():
    left = [
        _record(id="a-1", algorithm="AES", mode="CBC", key_size=128, file_path="f.py", line_number=1),
    ]
    right = [
        _record(id="b-1", algorithm="AES", mode="CBC", key_size=128, file_path="f.py", line_number=1),
        # a SECOND site using the same crypto — an addition, not a move
        _record(id="b-2", algorithm="AES", mode="CBC", key_size=128, file_path="g.py", line_number=2),
    ]
    result = semantic_diff(left, right)
    assert result["counts"] == {"added": 1, "removed": 0, "unchanged": 1, "changed": 0}
    assert result["added"][0]["location"] == "g.py"


def test_semantic_diff_added_removed_unchanged_still_work():
    left = [
        _record(id="a-1", algorithm="AES", mode="CBC", key_size=128, file_path="f.py", line_number=1),
        _record(id="a-2", algorithm="RSA", key_size=2048, file_path="g.py", line_number=2),
    ]
    right = [
        # identical to a-1
        _record(id="b-1", algorithm="AES", mode="CBC", key_size=128, file_path="f.py", line_number=1),
        # brand-new usage site
        _record(id="b-2", algorithm="Ed25519", file_path="h.py", line_number=3),
    ]
    result = semantic_diff(left, right)
    assert result["counts"] == {"added": 1, "removed": 1, "unchanged": 1, "changed": 0}
    assert result["added"][0]["algorithm"] == "Ed25519"
    assert result["removed"][0]["algorithm"] == "RSA"


def test_semantic_diff_boms_over_documents():
    bom_a = _bom([_record(id="a-1", algorithm="AES", mode="CBC", key_size=128, file_path="f.py", line_number=1)])
    bom_b = _bom([_record(id="b-1", algorithm="AES", mode="GCM", key_size=128, file_path="f.py", line_number=1)])
    result = semantic_diff_boms(bom_a, bom_b)
    assert result["counts"]["changed"] == 1
    assert result["changed"][0]["classifications"] == ["ALGORITHM_CHANGED"]
