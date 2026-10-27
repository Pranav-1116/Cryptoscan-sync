"""Actual session auth, request transaction and DB readback; not mocked endpoints."""
import copy
import pytest
from cbom.generator import CbomGenerator
from test_software_supply_chain_api import banks as banks
from db.models.system import System
from db.models.crypto_asset import CryptoAsset


def native():
    return CbomGenerator().from_records([{
        "id": "source-1", "algorithm": "ML-KEM-768", "key_size": 1184,
        "file_path": "declared/crypto.conf", "line_number": 1,
        "owner": "declared-owner", "application": "declared-payments",
        "data_classification": "confidential", "retention_years": 12,
    }], name="Payments", spec_version="1.6")


def ingest(client, bom=None, **kwargs):
    return client.post("/api/v1/cbom/ingest", json={"bom": bom or native(), "system_name": "Payments", **kwargs})


@pytest.mark.parametrize("role", ["readonly", "auditor", "developer", "scanner", "supervisor", "business_owner"])
def test_readonly_cannot_mutate_cbom_inventory(banks, role):
    clients, db, _ = banks
    from db.repositories.user_repository import UserRepository
    UserRepository(db).set_roles("reader_a", [role])
    db.commit()
    before = db.query(System).count()
    response = ingest(clients["reader_a"])
    assert response.status_code == 403, response.text
    db.expire_all()
    assert db.query(System).count() == before


def test_same_business_name_is_independent_in_two_banks(banks):
    clients, db, _ = banks
    first = ingest(clients["bank_a"])
    second = ingest(clients["bank_b"])
    assert first.status_code == second.status_code == 200
    assert first.json()["system"]["id"] != second.json()["system"]["id"]
    db.expire_all()
    rows = db.query(System).filter_by(name="Payments").all()
    assert {row.tenant_id for row in rows} == {"a", "b"}
    assert clients["bank_b"].get(f"/api/v1/cbom/system/{first.json()['system']['id']}?fmt=cyclonedx16").status_code == 404


def test_import_is_durable_declared_metadata_not_a_current_scan(banks):
    clients, db, _ = banks
    response = ingest(clients["bank_a"])
    assert response.status_code == 200, response.text
    payload = response.json()
    db.expire_all()
    system = db.get(System, payload["system"]["id"])
    assert system.last_scanned_at is None
    assert system.coverage_status != "CURRENT"
    assert system.extra["cbom"]["source"] == "ingest"
    assert system.extra["cbom"]["document_sha256"] == payload["document_sha256"]
    assert payload["source_basis"] == "IMPORTED_DECLARATIONS_NOT_SCANNER_OBSERVATIONS"
    row = db.query(CryptoAsset).filter_by(tenant_id="a").one()
    assert row.confidence != "HIGH"
    context = row.extra["cbom_import"]
    assert context["parameter_set_identifier"] == "768"
    assert context["key_size_basis"] == "REPORTED_UNIT_NOT_ESTABLISHED"
    assert context["business_contexts"][0]["owner"] == "declared-owner"
    exported = clients["bank_a"].get(f"/api/v1/cbom/system/{system.id}?fmt=cyclonedx16")
    assert exported.status_code == 200, exported.text
    assert "declared-owner" in exported.text and "confidential" in exported.text
    assert "IMPORTED_DECLARATIONS_NOT_SCANNER_OBSERVATIONS" in exported.text


def test_reimport_updates_mode_size_without_creating_duplicates(banks):
    clients, db, _ = banks
    bom = CbomGenerator().from_records([{"id":"one", "algorithm":"AES", "key_size":128,
          "mode":"CBC", "file_path":"crypto.cfg", "line_number":1}], spec_version="1.6")
    first = ingest(clients["bank_a"], bom)
    assert first.status_code == 200
    changed = copy.deepcopy(bom)
    changed["components"][0]["cryptoProperties"]["algorithmProperties"].update(mode="gcm",parameterSetIdentifier="256")
    result = ingest(clients["bank_a"], changed)
    assert result.status_code == 200, result.text
    db.expire_all()
    asset = db.query(CryptoAsset).filter_by(tenant_id="a").one()
    assert asset.mode == "gcm" and asset.key_size == 256
    assert asset.extra["cbom_import"]["document_sha256"] == result.json()["document_sha256"]


def test_top_level_signature_tampering_cannot_be_ingested(banks, monkeypatch):
    clients, db, _ = banks
    secret = "test-production-flow-signing-secret-only-123456"
    monkeypatch.setenv("CRYPTOSCAN_CBOM_SECRET", secret)
    signed = CbomGenerator().sign_standard(native(), secret, alg="HS256")
    from cbom.inventory import validate_document
    assert validate_document(signed)["ok"]  # exercise crypto verification, not schema rejection
    signed["components"][0]["name"] = "tampered"
    before = db.query(System).count()
    result = ingest(clients["bank_a"], signed)
    assert result.status_code == 422, result.text
    db.expire_all()
    assert db.query(System).count() == before


def test_flush_failure_rolls_back_every_import_change(banks, monkeypatch):
    from db.repositories.asset_repository import AssetRepository
    clients, db, _ = banks
    before = db.query(System).count()
    def fail(*args, **kwargs):
        raise RuntimeError("injected atomic-import failure")
    monkeypatch.setattr(AssetRepository, "replace_for_scan", fail)
    with pytest.raises(RuntimeError, match="injected atomic-import failure"):
        ingest(clients["bank_a"])
    db.expire_all()
    assert db.query(System).count() == before
    assert db.query(CryptoAsset).count() == 0


def test_commit_failure_is_not_reported_as_success(banks):
    from api.dependencies import get_db_session
    from db.connection.session import SessionLocal
    from sqlalchemy.exc import SQLAlchemyError
    clients, db, _ = banks
    before = db.query(System).count()
    def failed_transaction():
        with SessionLocal() as session:
            def fail():
                raise SQLAlchemyError("injected commit failure")
            session.commit = fail
            try:
                yield session
            finally:
                session.rollback()
    clients["bank_a"].app.dependency_overrides[get_db_session] = failed_transaction
    result = ingest(clients["bank_a"])
    assert result.status_code == 503, result.text
    assert "unconfirmed" in result.json()["detail"]
    db.expire_all()
    assert db.query(System).count() == before
    assert db.query(CryptoAsset).count() == 0


def test_imports_do_not_overwrite_scanners_or_other_app_context(banks):
    from db.repositories.asset_repository import AssetRepository
    from db.tenancy import tenant_scope
    clients, db, _ = banks
    with tenant_scope("a"):
        measured = AssetRepository(db).replace_for_scan("actual-scan", [{
            "algorithm": "ML-KEM-768", "purpose":"kem", "key_size":1184,
            "file_path":"declared/crypto.conf", "line_number":1, "confidence":"HIGH"}])[0]
        measured_id = measured.id
        db.commit()
    first = ingest(clients["bank_a"])
    second = clients["bank_a"].post("/api/v1/cbom/ingest", json={"bom":native(), "system_name":"Another application"})
    assert first.status_code == second.status_code == 200
    db.expire_all()
    assert db.query(CryptoAsset).filter_by(tenant_id="a").count() == 3
    measured = db.get(CryptoAsset, measured_id)
    assert measured.confidence == "HIGH" and not measured.extra.get("cbom_import")
    # A later scanner refresh must not rewrite either imported declaration.
    with tenant_scope("a"):
        AssetRepository(db).replace_for_scan("actual-scan-2", [{
            "algorithm":"ML-KEM-768", "purpose":"kem", "key_size":999,
            "file_path":"declared/crypto.conf", "line_number":1, "confidence":"HIGH"}])
        db.commit()
    db.expire_all()
    assert db.get(CryptoAsset, measured_id).key_size == 999
    assert sorted(a.key_size for a in db.query(CryptoAsset).filter_by(tenant_id="a").all()) == [999,1184,1184]


@pytest.mark.parametrize("change", ["algorithm_length", "negative_line", "huge_key", "nested_context", "nonfinite"])
def test_invalid_storage_metadata_is_422_and_has_no_side_effects(banks, change):
    clients, db, _ = banks
    bom = native()
    component = bom["components"][0]
    if change == "algorithm_length":
        next(p for p in component["properties"] if p["name"] == "cryptoscan:reported_algorithm")["value"] = "X" * 81
    elif change == "negative_line":
        component["evidence"]["occurrences"][0]["line"] = -1
    elif change == "huge_key":
        next(p for p in component["properties"] if p["name"] == "cryptoscan:reported_key_size")["value"] = str(2**32)
    elif change == "nested_context":
        next(p for p in component["properties"] if p["name"] == "cryptoscan:business_context")["value"] = '{"owner":{"untrusted":"nested raw object"}}'
    else:
        # Legacy accepts arbitrary property values; JSON nonfinite values must
        # still be rejected before writing. HTTPX correctly refuses to encode
        # this; send explicit bytes to exercise the actual request parser.
        result = clients["bank_a"].post("/api/v1/cbom/ingest", content=b'{"bom":{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"type":"cryptographic-asset","name":"AES"}],"metadata":{"properties":[{"name":"extra","value":NaN}]}},"system_name":"Payments"}', headers={"Content-Type":"application/json"})
        assert result.status_code == 422, result.text
        assert db.query(System).filter_by(name="Payments").count() == 0
        return
    result = ingest(clients["bank_a"], bom)
    assert result.status_code == 422, result.text
    assert db.query(System).filter_by(name="Payments").count() == 0


def test_import_does_not_clear_existing_scan_failure(banks):
    clients, db, _ = banks
    from datetime import datetime, timezone
    system = System(name="Payments", tenant_id="a", coverage_status="FAILED",
                    last_scan_id="prior-scan", last_scanned_at=datetime(2025,1,1,tzinfo=timezone.utc))
    db.add(system); db.commit()
    result = ingest(clients["bank_a"])
    assert result.status_code == 200
    db.expire_all()
    assert system.coverage_status == "FAILED" and system.last_scan_id == "prior-scan"
    assert system.last_scanned_at.year == 2025


def test_import_receipt_and_audit_survive_a_later_real_scan_stamp(banks):
    import json
    from db.models.user import AuditLog
    from db.repositories.system_repository import SystemRepository
    from db.tenancy import tenant_scope
    clients, db, _ = banks
    result = ingest(clients["bank_a"])
    assert result.status_code == 200
    receipt = result.json()
    db.expire_all()
    system = db.get(System, receipt["system"]["id"])
    assert system.extra["cbom_import"]["imported_by"] == "bank_a"
    event = db.query(AuditLog).filter_by(action="cbom.ingest", target_id=system.id).one()
    assert event.actor == "bank_a"
    assert json.loads(event.detail)["document_sha256"] == receipt["document_sha256"]
    with tenant_scope("a"):
        SystemRepository(db).stamp_scan(system.id, scan_id="actual-scan", component_count=3)
        db.commit()
    db.expire_all()
    assert system.extra["cbom"]["source"] == "scan"
    assert system.extra["cbom_import"]["document_sha256"] == receipt["document_sha256"]
    again = ingest(clients["bank_a"])
    assert again.status_code == 200
    db.expire_all()
    assert system.extra["cbom"]["source"] == "scan" and system.last_scan_id == "actual-scan"


def test_scalar_supplier_context_survives_reexport(banks):
    clients, db, _ = banks
    bom = native()
    bom["components"][0]["properties"] = [p for p in bom["components"][0]["properties"] if p["name"] != "cryptoscan:business_context"]
    result = ingest(clients["bank_a"], bom)
    assert result.status_code == 200
    db.expire_all()
    context = db.query(CryptoAsset).filter_by(tenant_id="a").one().extra["cbom_import"]
    assert context["business_contexts"][0]["owner"] == "declared-owner"
    exported = clients["bank_a"].get(f"/api/v1/cbom/system/{result.json()['system']['id']}?fmt=cyclonedx16")
    assert exported.status_code == 200 and "declared-owner" in exported.text


@pytest.mark.parametrize("metadata", ["wrong", {"component":"wrong"}, {"properties":["wrong"]}, {"properties":[{"name":[],"value":"wrong"}]}])
def test_malformed_legacy_metadata_is_422(banks, metadata):
    clients, db, _ = banks
    bom = {"bomFormat":"CycloneDX","specVersion":"1.5","metadata":metadata,
           "components":[{"type":"cryptographic-asset","name":"AES"}]}
    result = ingest(clients["bank_a"],bom)
    assert result.status_code == 422
    assert db.query(System).filter_by(name="Payments").count() == 0


def test_nested_native_components_are_not_silently_partially_imported(banks):
    from cbom.inventory import validate_document
    clients, db, _ = banks
    bom = native()
    nested = copy.deepcopy(bom["components"][0])
    nested["bom-ref"] = "nested-source"
    bom["components"].append({"type":"library", "name":"parent", "bom-ref":"parent", "components":[nested]})
    assert validate_document(bom)["ok"]
    response = ingest(clients["bank_a"], bom)
    assert response.status_code == 422 and "flat" in response.json()["detail"]
    assert db.query(System).filter_by(name="Payments").count() == 0


def test_native_protocol_is_not_misrepresented_as_an_algorithm(banks):
    from cbom.inventory import validate_document
    clients, db, _ = banks
    bom = native()
    bom["components"][0]["cryptoProperties"] = {"assetType":"protocol", "protocolProperties":{"type":"tls", "version":"1.3"}}
    assert validate_document(bom)["ok"]
    response = ingest(clients["bank_a"],bom)
    assert response.status_code == 422 and "algorithm metadata only" in response.json()["detail"]
    assert db.query(System).filter_by(name="Payments").count() == 0


def test_native_padding_survives_database_readback(banks):
    clients, db, _ = banks
    bom = CbomGenerator().from_records([{"id":"oaep", "algorithm":"RSA", "key_size":2048,
              "padding":"OAEP", "file_path":"declared/rsa.conf", "line_number":1}], spec_version="1.6")
    response = ingest(clients["bank_a"],bom)
    assert response.status_code == 200
    exported = clients["bank_a"].get(f"/api/v1/cbom/system/{response.json()['system']['id']}?fmt=cyclonedx16")
    assert exported.status_code == 200
    assert exported.json()["components"][0]["cryptoProperties"]["algorithmProperties"]["padding"] == "oaep"
