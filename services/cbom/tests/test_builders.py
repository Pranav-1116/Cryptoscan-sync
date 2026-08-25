from cbom.builders.component_builder import build_component
from cbom.builders.metadata_builder import build_metadata
from cbom.mappers.oid_lookup import lookup_oid
from cbom.validator import validate_cbom


def test_component_and_metadata_builders():
    component = build_component(
        {"id": "e1", "algorithm": "AES-256", "mode": "GCM", "file_path": "a.py", "line_number": 3}
    )
    assert component["name"] in {"AES-256", "AES"}
    assert component["cryptoProperties"]["oid"] == lookup_oid("AES-256")
    meta = build_metadata(name="demo", version="1.0")
    assert meta["component"]["name"] == "demo"
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [component],
    }
    result = validate_cbom(bom)
    assert result["ok"]
