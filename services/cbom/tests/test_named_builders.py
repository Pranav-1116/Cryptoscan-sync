from cbom.builders.dependency_builder import build_dependencies
from cbom.builders.evidence_builder import build_evidence
from cbom.builders.vulnerability_builder import build_vulnerabilities
from cbom.mappers.asset_type_mapper import map_asset_type
from cbom.mappers.confidence_float_mapper import confidence_to_float
from cbom.mappers.security_level_calculator import calculate_pq_level, calculate_sec_level
from cbom.models.cbom_document import CbomDocument


def test_builders_and_mappers():
    component = {
        "bom-ref": "crypto-asset-1",
        "name": "AES-256",
        "type": "cryptographic-asset",
        "cryptoProperties": {"assetType": "algorithm"},
    }
    deps = build_dependencies([component], name="payment-api")
    assert deps[0]["ref"] == "payment-api"
    assert "crypto-asset-1" in deps[0]["dependsOn"]
    vulns = build_vulnerabilities(
        [{"cve": "CVE-2023-0215", "severity": "HIGH", "summary": "uaf", "package": "openssl"}]
    )
    assert vulns[0]["id"] == "CVE-2023-0215"
    evidence = build_evidence({"id": "e1", "algorithm": "AES", "file_path": "a.py", "line_number": 4})
    assert evidence["file"] == "a.py"
    assert map_asset_type({"algorithm": "AES"}) == "algorithm"
    assert map_asset_type({"library": "openssl"}) == "related-crypto-material"
    assert calculate_sec_level({"algorithm": "AES-256"}) == 256
    assert calculate_sec_level({"algorithm": "RSA", "key_size": 2048}) == 112
    assert calculate_pq_level({"algorithm": "RSA"}) == 0
    assert calculate_pq_level({"algorithm": "ML-KEM-768"}) == 3
    assert confidence_to_float("VERIFIED") == 1.0
    doc = CbomDocument.from_dict(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [component],
            "dependencies": deps,
            "vulnerabilities": vulns,
        }
    )
    assert doc.to_dict()["components"][0]["name"] == "AES-256"
