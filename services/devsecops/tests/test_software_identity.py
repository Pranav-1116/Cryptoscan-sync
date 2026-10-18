from copy import deepcopy
import pytest
from devsecops.software_identity import sbom_components


def test_nested_cyclonedx_components_keep_refs_without_modifying_original():
    child = {"bom-ref": "child", "name": "crypto", "purl": "pkg:pypi/crypto@1.0", "version": "1.0"}
    doc = {"bomFormat": "CycloneDX", "components": [{"bom-ref": "parent", "name": "app", "components": [child]}]}
    before = deepcopy(doc)
    rows = sbom_components(doc)
    assert [row["bom_ref"] for row in rows] == ["parent", "child"]
    assert rows[1]["package_identity"] == child["purl"]
    assert rows[0]["package_identity"] is None
    assert doc == before


def test_nested_component_bounds_refuse_partial_results(monkeypatch):
    import devsecops.software_identity as identity
    monkeypatch.setattr(identity, "MAX_COMPONENTS", 1)
    with pytest.raises(ValueError, match="limit"):
        sbom_components({"bomFormat": "CycloneDX", "components": [{"name": "a", "components": [{"name": "b"}]}]})


def test_conflicting_version_is_preserved_but_ineligible_for_exact_exposure_join():
    rows = sbom_components({"bomFormat": "CycloneDX", "components": [
        {"name": "crypto", "version": "2.0", "purl": "pkg:pypi/crypto@1.0"}]})
    assert rows[0]["version"] == "2.0"
    assert rows[0]["package_identity"] is None
