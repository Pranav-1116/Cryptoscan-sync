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


# ---------------------------------------------------- estate dependency edges

from cbom.builders.dependency_builder import build_estate_dependencies, infer_library_edges


def test_estate_dependencies_link_system_to_assets_and_neighbours():
    edges = [{"parent": "sys-pay", "child": "sys-db"},
             {"parent": "sys-web", "child": "sys-pay"}]
    deps = build_estate_dependencies("sys-pay", ["ca-1", "ca-2"], edges)
    by_ref = {d["ref"]: d["dependsOn"] for d in deps}
    # the system depends on its crypto assets AND its registered child system
    assert by_ref["system:sys-pay"] == ["ca-1", "ca-2", "system:sys-db"]
    # upstream callers keep their direction — that edge is the whole point
    assert by_ref["system:sys-web"] == ["system:sys-pay"]


def test_estate_dependencies_without_edges_is_assets_only():
    deps = build_estate_dependencies("sys-pay", ["ca-1"])
    assert deps == [{"ref": "system:sys-pay", "dependsOn": ["ca-1"]}]


def test_estate_dependencies_empty_system_yields_nothing():
    assert build_estate_dependencies("sys-pay", []) == []


def test_infer_library_edges_use_real_bom_refs():
    edges = infer_library_edges([{"id": "ca-1", "library": "BouncyCastle"}])
    assert edges == [{"ref": "ca-1", "dependsOn": ["library:BouncyCastle"]}]
