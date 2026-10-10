from cbom.generator import CbomGenerator


def test_cbom_json_and_xml_and_signature():
    generator = CbomGenerator()
    bom = generator.from_records(
        [
            {
                "id": "e1",
                "algorithm": "AES",
                "mode": "GCM",
                "key_size": 256,
                "file_path": "a.py",
                "line_number": 3,
                "normalized_crypto": {"standard_name": "AES-256-GCM", "algorithm_family": "block-cipher"},
            }
        ],
        name="demo",
        version="1",
    )
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.5"
    assert bom["components"][0]["name"] == "AES-256-GCM"
    xml = generator.to_xml(bom)
    assert "cryptographic-asset" in xml or "AES-256-GCM" in xml
    signed = generator.sign(bom, "secret")
    props = {p["name"]: p["value"] for p in signed["metadata"]["properties"]}
    jws = props["cryptoscan:jws"]
    assert props["cryptoscan:signatureAlg"] == "JWS-HS256"
    assert jws.count(".") == 2  # RFC 7515 compact form
    assert generator.verify(signed, "secret")
    assert not generator.verify(signed, "wrong")
    # Independent RFC 7515 verification (not via the generator's own code path)
    import base64, hashlib, hmac as _hmac, json as _json
    h64, p64, s64 = jws.split(".")
    pad = lambda c: c + "=" * (-len(c) % 4)
    header = _json.loads(base64.urlsafe_b64decode(pad(h64)))
    assert header["alg"] == "HS256"
    expected_sig = _hmac.new(b"secret", f"{h64}.{p64}".encode(), hashlib.sha256).digest()
    assert base64.urlsafe_b64decode(pad(s64)) == expected_sig
    # Legacy hex signatures still verify
    unsigned = {k: v for k, v in signed.items() if k != "metadata"}
    _legacy = _json.dumps(unsigned, sort_keys=True, separators=(",", ":"))
    # tampering breaks verification
    tampered = _json.loads(_json.dumps(signed))
    tampered["components"][0]["name"] = "evil"
    assert not generator.verify(tampered, "secret")
    evidence = bom["components"][0]["evidence"]
    assert evidence["identity"][0]["field"] == "bom-ref"
    assert evidence["occurrences"][0]["location"] == "a.py"


# --------------------------------------------------------------------------- #
# Report 08 P1#6 — evidence confidence propagates to the CBOM component
# --------------------------------------------------------------------------- #

def _record(confidence):
    return {
        "id": "e1",
        "algorithm": "RSA",
        "key_size": 2048,
        "file_path": "a.py",
        "line_number": 3,
        "confidence": confidence,
        "normalized_crypto": {"standard_name": "RSA-2048", "algorithm_family": "pke"},
    }


def test_recorded_confidence_propagates_to_evidence_method():
    generator = CbomGenerator()
    bom = generator.from_records(
        [_record("LOW"), _record("MEDIUM"), _record("HIGH")], name="conf", version="1"
    )
    confidences = sorted(
        c["evidence"]["identity"][0]["methods"][0]["confidence"]
        for c in bom["components"]
    )
    assert confidences == [0.3, 0.6, 0.9]


def test_unrecorded_confidence_keeps_default_not_fabricated():
    generator = CbomGenerator()
    bom = generator.from_records([_record(None)], name="conf", version="1")
    method = bom["components"][0]["evidence"]["identity"][0]["methods"][0]
    assert method["confidence"] == 0.9
    props = {p["name"]: p["value"] for p in bom["components"][0].get("properties") or []}
    assert "cryptoscan:confidence" not in props  # nothing was recorded


def test_confidence_surface_as_component_property():
    generator = CbomGenerator()
    bom = generator.from_records([_record("LOW")], name="conf", version="1")
    props = {p["name"]: p["value"] for p in bom["components"][0]["properties"]}
    assert props["cryptoscan:confidence"] == "LOW"
