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
    assert len(props["cryptoscan:signature"]) == 64
