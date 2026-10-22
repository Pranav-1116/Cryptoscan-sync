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


def quality_document(fmt, version):
    from urllib.parse import quote
    purl = "pkg:maven/org.bank/crypto@" + quote(version, safe="")
    if fmt == "cyclonedx":
        return {"bomFormat": "CycloneDX", "components": [
            {"name": "crypto", "version": version, "purl": purl, "bom-ref": "crypto"}]}
    return {"spdxVersion": "SPDX-2.3", "packages": [{
        "name": "crypto", "versionInfo": version, "SPDXID": "SPDXRef-crypto",
        "externalRefs": [{"referenceType": "purl", "referenceLocator": purl}]}]}


@pytest.mark.parametrize("fmt", ["cyclonedx", "spdx"])
@pytest.mark.parametrize("version", ["${crypto.version}", "1.x", "[1.0,2.0)"])
def test_quality_increment_sbom_keeps_unresolved_version_and_document(fmt, version):
    doc = quality_document(fmt, version)
    before = deepcopy(doc)
    component = sbom_components(doc)[0]
    assert component["package_identity"] is None
    assert component["version"] == version
    assert doc == before


@pytest.mark.parametrize("fmt", ["cyclonedx", "spdx"])
def test_quality_increment_concrete_sbom_version_stays_resolved(fmt):
    doc = quality_document(fmt, "1.0.Final")
    component = sbom_components(doc)[0]
    assert component["package_identity"] == "pkg:maven/org.bank/crypto@1.0.Final"
