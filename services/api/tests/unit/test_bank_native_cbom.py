"""Bank questions O1/O4/O5/D1/G2: tenant-scoped native downloads, not a catalog."""
import pytest
from cbom.cyclonedx16 import validate_cyclonedx16
from cbom.generator import CbomGenerator
from test_software_supply_chain_api import banks as banks
from test_cross_surface_estate_contract import estate as estate


@pytest.mark.parametrize("who", ["bank_a", "bank_b", "platform_admin"])
def test_portfolio_native16_is_a_real_validated_cbom_for_current_estate(estate, who):
    clients, _, _ = estate
    response = clients[who].get("/api/v1/cbom/portfolio?fmt=cyclonedx16")
    assert response.status_code == 200, response.text
    assert response.json()["specVersion"] == "1.6"
    assert validate_cyclonedx16(response.json())["ok"], response.text
    for other in {"bank_a", "bank_b", "platform_admin"} - {who}:
        assert "private-" + other not in response.text


@pytest.mark.parametrize("who", ["bank_a", "bank_b", "platform_admin"])
def test_scan_export_native16_preserves_tenant_filter_and_real_evidence(estate, who):
    clients, _, rows = estate
    own = rows[who][0]
    response = clients[who].get(f"/api/v1/scans/{own.id}/cbom?spec_version=1.6")
    assert response.status_code == 200, response.text
    assert response.json()["specVersion"] == "1.6"
    assert validate_cyclonedx16(response.json())["ok"], response.text
    assert "private-" + who in response.text
    for other in {"bank_a", "bank_b", "platform_admin"} - {who}:
        result = clients[who].get(f"/api/v1/scans/{rows[other][0].id}/cbom?spec_version=1.6")
        assert result.status_code == 404
        assert "private-" not in result.text


def test_standard_signing_happens_after_conversion_and_is_valid(estate):
    clients, _, _ = estate
    response = clients["bank_a"].get("/api/v1/cbom/portfolio?fmt=cyclonedx16&signed=true")
    assert response.status_code == 200, response.text
    bom = response.json()
    assert bom["specVersion"] == "1.6"
    assert validate_cyclonedx16(bom)["ok"]
    props = {p["name"]: p["value"] for p in bom["metadata"]["properties"]}
    assert "cryptoscan:jws" in props


def test_unknown_format_is_rejected_not_silently_mislabeled(estate):
    clients, _, rows = estate
    assert clients["bank_a"].get("/api/v1/cbom/portfolio?fmt=made-up").status_code == 422
    scan = rows["bank_a"][0]
    assert clients["bank_a"].get(f"/api/v1/scans/{scan.id}/cbom?spec_version=2.0").status_code == 422


def test_validate_endpoint_uses_full_schema_for_native16(estate):
    clients, _, _ = estate
    bom = CbomGenerator().from_records([{"id": "a", "algorithm": "AES"}], spec_version="1.6")
    bom["components"][0]["cryptoProperties"]["algorithmProperties"]["mode"] = "NOT-A-STANDARD-MODE"
    response = clients["bank_a"].post("/api/v1/cbom/validate", json={"bom": bom})
    assert response.status_code == 200, response.text
    assert response.json()["ok"] is False


@pytest.mark.parametrize("version", ["1.5", "1.6"])
def test_quarantined_evidence_cannot_escape_through_cbom_export(estate, version):
    from datetime import datetime, timezone
    from db.models.evidence_disposition import EvidenceDisposition
    clients, db, rows = estate
    scan = rows["bank_a"][0]
    db.add(EvidenceDisposition(tenant_id="a", scan_id=scan.id, decision="QUARANTINE_EXPORTS",
                              decided_by="bank_a", decided_at=datetime.now(timezone.utc)))
    db.commit()
    response = clients["bank_a"].get(f"/api/v1/scans/{scan.id}/cbom?spec_version={version}")
    assert response.status_code == 409, response.text
    assert "private-bank_a" not in response.text
    assert clients["bank_a"].get(f"/api/v1/cbom/scan/{scan.id}?fmt=cyclonedx16").status_code == 409


@pytest.mark.parametrize("path", ["portfolio", "system/system-a"])
def test_bank_owner_classification_and_shared_asset_are_exported_without_duplicate_refs(estate, path):
    from db.models.system import System
    from db.models.system_asset import SystemAsset
    from db.models.system_dependency import SystemDependency
    from db.models.crypto_asset import CryptoAsset
    clients, db, _ = estate
    system = db.get(System, "system-a")
    system.owner = "payments-team"
    system.extra = {"data_classification": "PAN", "data_retention_years": 10}
    db.add(System(id="ledger-a", tenant_id="a", name="Ledger a", owner="ledger-team"))
    db.add(CryptoAsset(id="shared-a", tenant_id="a", algorithm="RSA", key_size=2048, file_path="payments/crypto.py"))
    db.flush()
    db.add_all([SystemAsset(tenant_id="a", system_id="system-a", asset_id="shared-a"),
                SystemAsset(tenant_id="a", system_id="ledger-a", asset_id="shared-a"),
                SystemDependency(tenant_id="a", parent_id="system-a", child_id="ledger-a", relation="CALLS")])
    db.commit()
    response = clients["bank_a"].get(f"/api/v1/cbom/{path}?fmt=cyclonedx16")
    assert response.status_code == 200, response.text
    bom = response.json()
    assert validate_cyclonedx16(bom)["ok"]
    asset = [c for c in bom["components"] if c["bom-ref"] == "shared-a"]
    assert len(asset) == 1
    props = {p["name"]: p["value"] for p in asset[0]["properties"]}
    # Portfolio has multiple declared contexts, never one invented resolved owner.
    assert "payments-team" in str(asset[0]["properties"])
    assert "10" in str(asset[0]["properties"])
    assert "PAN" in str(asset[0]["properties"])
    assert props["cryptoscan:deployment_readiness"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("metadata", [["opaque"], "opaque", {"component": [1]}])
def test_native_validation_does_not_parse_schema_invalid_metadata_or_return500(estate, metadata):
    clients, _, _ = estate
    response = clients["bank_a"].post("/api/v1/cbom/validate", json={"bom": {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": metadata, "components": []}})
    assert response.status_code == 200, response.text
    assert response.json()["ok"] is False
    assert response.json()["name"] is None
