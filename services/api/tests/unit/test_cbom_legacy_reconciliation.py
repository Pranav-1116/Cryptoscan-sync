"""Historical imports must not become scanner proof, or destroy real evidence."""
from datetime import datetime, timezone

import pytest
from sqlalchemy import event
from test_software_supply_chain_api import banks as banks
from test_cbom_production_flow import ingest
from db.models.crypto_asset import CryptoAsset
from db.models.system import System
from db.models.system_asset import SystemAsset
from db.repositories.asset_repository import AssetRepository
from db.repositories.system_repository import SystemRepository
from db.tenancy import tenant_scope


def legacy(db, *, tenant="a", name="Payments", shared_with=None):
    system = System(tenant_id=tenant, name=name, coverage_status="CURRENT",
                    last_scanned_at=datetime.now(timezone.utc), scan_target="/synthetic/payments")
    asset = CryptoAsset(tenant_id=tenant, algorithm="ML-KEM-768", purpose="kem", key_size=1184,
                        file_path="declared/crypto.conf", line_number=1, confidence="HIGH",
                        scanner_ids=["cbom-ingest"], extra={"scan_id":"cbom-ingest:historical"})
    db.add_all([system, asset]); db.flush()
    db.add(SystemAsset(tenant_id=tenant, system_id=system.id, asset_id=asset.id))
    if shared_with:
        db.add(SystemAsset(tenant_id=tenant, system_id=shared_with.id, asset_id=asset.id))
    db.commit()
    return system.id, asset.id


def detail(client, system_id):
    response = client.get(f"/api/v1/cbom/system/{system_id}/legacy-imports")
    assert response.status_code == 200, response.text
    return response.json()


def reconcile(client, system_id, snapshot=None):
    state = snapshot or detail(client, system_id)
    return client.post(f"/api/v1/cbom/system/{system_id}/reconcile-legacy", json={
        "expected_snapshot_sha256":state["snapshot_sha256"],
        "replacement_document_sha256":state["replacement_document_sha256"] or "0"*64,
        "reason":"Original synthetic declaration reviewed and reimported; no measured evidence claimed.",
    })


def test_legacy_read_projection_and_coverage_do_not_rewrite_history(banks):
    clients, db, _ = banks
    sid, aid = legacy(db)
    response = clients["bank_a"].get("/api/v1/cbom/coverage")
    assert response.status_code == 200, response.text
    assert response.json()["counts"]["CURRENT"] == 0
    assert response.json()["legacy_coverage_unproven"] == 1
    with tenant_scope("a"):
        repo = SystemRepository(db)
        assert repo.list_systems(coverage="CURRENT")[1] == 0
        assert repo.list_systems(coverage="NEVER_SCANNED")[1] == 1
        projected = db.get(CryptoAsset, aid).to_dict()
        assert projected["confidence"] == "LOW"
        assert projected["reported_confidence"] == "HIGH"
        assert projected["source_basis"] == "LEGACY_IMPORT_REVIEW_REQUIRED"
        assert repo.catalog_row(db.get(System, sid))["coverage_status"] == "NEVER_SCANNED"
    db.expire_all()
    assert db.get(CryptoAsset, aid).confidence == "HIGH"
    assert db.get(System, sid).coverage_status == "CURRENT"
    assert db.get(System, sid).last_scanned_at is not None


def test_legacy_is_visible_but_cannot_be_exported_as_clean_proof(banks):
    clients, db, _ = banks
    sid, aid = legacy(db)
    state = detail(clients["bank_a"], sid)
    assert state["pending_assets"] == 1 and state["mixed_evidence_assets"] == 0
    for path in (f"/api/v1/cbom/system/{sid}", "/api/v1/cbom/portfolio"):
        response = clients["bank_a"].get(path)
        assert response.status_code == 409, response.text
        assert "historical" in response.text.lower()
    assert clients["bank_b"].get(f"/api/v1/cbom/system/{sid}/legacy-imports").status_code == 404
    assert clients["reader_a"].post(f"/api/v1/cbom/system/{sid}/reconcile-legacy", json={}).status_code == 403


def test_reconciliation_requires_reimport_and_retains_original_records(banks):
    from db.models.user import AuditLog
    clients, db, _ = banks
    sid, aid = legacy(db)
    assert reconcile(clients["bank_a"], sid).status_code == 409
    receipt = ingest(clients["bank_a"])
    assert receipt.status_code == 200, receipt.text
    response = reconcile(clients["bank_a"], sid)
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["detached_assets"] == result["archived_declarations"] == 1
    db.expire_all()
    original = db.get(CryptoAsset, aid)
    assert original.confidence == "HIGH" and original.scanner_ids == ["cbom-ingest"]
    assert original.extra["scan_id"] == "cbom-ingest:historical"
    assert original.extra["legacy_cbom_disposition"]["audit_id"] == result["audit_id"]
    assert db.get(AuditLog, result["audit_id"]).action == "cbom.legacy_reconciled"
    assert db.get(System, sid).coverage_status == "CURRENT"  # raw historical label retained
    assert clients["bank_a"].get("/api/v1/cbom/coverage").json()["counts"]["CURRENT"] == 0
    exported = clients["bank_a"].get(f"/api/v1/cbom/system/{sid}?fmt=cyclonedx16")
    assert exported.status_code == 200, exported.text
    assert "IMPORTED_DECLARATIONS_NOT_SCANNER_OBSERVATIONS" in exported.text
    portfolio = clients["bank_a"].get("/api/v1/cbom/portfolio?fmt=cyclonedx16")
    assert portfolio.status_code == 200, portfolio.text
    assert len([c for c in portfolio.json()["components"] if c["type"] == "cryptographic-asset" and c["name"] == "ML-KEM-768"]) == 1
    assert detail(clients["bank_a"], sid)["pending_assets"] == 0


def test_stale_review_cannot_apply_after_another_import(banks):
    clients, db, _ = banks
    sid, aid = legacy(db)
    ingest(clients["bank_a"])
    snapshot = detail(clients["bank_a"], sid)
    ingest(clients["bank_a"])
    result = reconcile(clients["bank_a"], sid, snapshot)
    assert result.status_code == 409, result.text
    db.expire_all()
    assert db.query(SystemAsset).filter_by(system_id=sid, asset_id=aid).count() == 1


def test_shared_legacy_is_not_globally_archived_by_one_system(banks):
    clients, db, _ = banks
    other = System(tenant_id="a", name="Other payments", coverage_status="CURRENT")
    db.add(other); db.commit()
    sid, aid = legacy(db, shared_with=other)
    ingest(clients["bank_a"])
    response = reconcile(clients["bank_a"], sid)
    assert response.status_code == 200, response.text
    assert response.json()["archived_declarations"] == 0
    db.expire_all()
    assert "legacy_cbom_disposition" not in db.get(CryptoAsset, aid).extra
    assert detail(clients["bank_a"], other.id)["pending_assets"] == 1
    assert clients["bank_a"].get("/api/v1/cbom/portfolio").status_code == 409


@pytest.mark.parametrize("modern", [False, True])
def test_scanner_and_cloud_do_not_overwrite_any_import_namespace(banks, modern):
    clients, db, _ = banks
    if modern:
        assert ingest(clients["bank_a"]).status_code == 200
        aid = db.query(CryptoAsset).filter_by(tenant_id="a").one().id
    else:
        _, aid = legacy(db)
    with tenant_scope("a"):
        original = db.get(CryptoAsset, aid)
        old_extra = dict(original.extra)
        measured = AssetRepository(db).replace_for_scan("real-new-scan", [{
            "algorithm":"ML-KEM-768", "purpose":"kem", "file_path":original.file_path,
            "line_number":1, "confidence":"HIGH", "key_size":1184}])[0]
        assert measured.id != aid
        # Cloud query must distinguish declaration rows even when no scan row exists.
        cloud, created = AssetRepository(db).upsert_cloud_asset({
            "algorithm":"AES", "file_path":"cloud://synthetic/key", "key_size":256})
        assert created
        declaration = CryptoAsset(algorithm="AES", purpose="encryption", file_path=cloud.file_path,
                                  line_number=0, scanner_ids=["cbom-ingest"], extra={"scan_id":"cbom-ingest:old"})
        db.add(declaration); db.flush()
        again, created = AssetRepository(db).upsert_cloud_asset({
            "algorithm":"AES", "file_path":cloud.file_path, "key_size":128})
        assert not created and again.id == cloud.id
        assert original.extra == old_extra


def test_portfolio_limits_rows_in_sql_not_after_fetch(banks, monkeypatch):
    from api.routers.cbom import _located_assets
    clients, db, _ = banks
    with tenant_scope("a"):
        db.add_all([CryptoAsset(algorithm="AES", file_path=f"/synthetic/{i}", line_number=0) for i in range(7)])
        db.commit()
        monkeypatch.setenv("PORTFOLIO_MAX_ASSETS", "3")
        statements = []
        def record(conn, cursor, statement, parameters, context, executemany):
            statements.append(statement)
        event.listen(db.get_bind(), "before_cursor_execute", record)
        try:
            rows, total = _located_assets(db)
        finally:
            event.remove(db.get_bind(), "before_cursor_execute", record)
        assert total == 7 and len(rows) == 3
        payload_selects = [s for s in statements if "crypto_assets.algorithm" in s]
        assert len(payload_selects) == 1 and "LIMIT" in payload_selects[0].upper()


def test_mixed_evidence_is_refused_without_touching_committed_finding(banks):
    from db.models.base import BaseModel
    from db.models.scan import Scan
    from db.models.evidence_record import EvidenceRecord
    from db.models.crypto_asset_evidence import CryptoAssetEvidence
    clients, db, _ = banks
    sid, aid = legacy(db)
    scan = Scan(tenant_id="a", target_location="synthetic-only", scan_start=datetime.now(timezone.utc), status="COMPLETED")
    db.add(scan); db.flush()
    evidence = EvidenceRecord(tenant_id="a", scan_id=scan.id, content_hash="a"*64, chain_hash="b"*64,
        chain_position=1, algorithm="ML-KEM-768", confidence="HIGH", file_path="synthetic-only", line_number=1,
        finding_data={"synthetic":"unchanged raw finding"})
    db.add(evidence); db.flush()
    db.add(CryptoAssetEvidence(tenant_id="a", asset_id=aid, evidence_id=evidence.id)); db.commit()
    db.expire_all()
    before = BaseModel.to_dict(db.get(EvidenceRecord, evidence.id))
    assert ingest(clients["bank_a"]).status_code == 200
    state = detail(clients["bank_a"], sid)
    assert state["mixed_evidence_assets"] == 1
    assert "unchanged raw finding" not in str(state)
    result = reconcile(clients["bank_a"], sid, state)
    assert result.status_code == 409 and "linked scanner evidence" in result.text
    db.expire_all()
    assert BaseModel.to_dict(db.get(EvidenceRecord, evidence.id)) == before
    assert db.query(SystemAsset).filter_by(system_id=sid, asset_id=aid).count() == 1


def test_completed_same_tenant_scan_can_supersede_unproven_coverage(banks):
    from db.models.scan import Scan
    clients, db, _ = banks
    sid, _ = legacy(db)
    scan = Scan(tenant_id="a", target_location="synthetic-only", scan_start=datetime.now(timezone.utc), status="COMPLETED")
    db.add(scan); db.flush()
    db.get(System, sid).last_scan_id = scan.id; db.commit()
    response = clients["bank_a"].get("/api/v1/cbom/coverage")
    assert response.json()["counts"]["CURRENT"] == 1
    # It does not clear the legacy inventory provenance or the export block.
    assert clients["bank_a"].get(f"/api/v1/cbom/system/{sid}").status_code == 409


@pytest.mark.parametrize("status,tenant", [("RUNNING","a"),("FAILED","a"),("COMPLETED","b")])
def test_failed_running_and_foreign_scans_are_not_coverage_proof(banks, status, tenant):
    from db.models.scan import Scan
    clients, db, _ = banks
    sid, _ = legacy(db)
    scan = Scan(tenant_id=tenant, target_location="synthetic-only", scan_start=datetime.now(timezone.utc), status=status)
    db.add(scan); db.flush(); db.get(System, sid).last_scan_id = scan.id; db.commit()
    assert clients["bank_a"].get("/api/v1/cbom/coverage").json()["counts"]["CURRENT"] == 0


def test_incomplete_replacement_cannot_erase_other_historical_identities(banks):
    clients, db, _ = banks
    sid, _ = legacy(db)
    asset = CryptoAsset(tenant_id="a", algorithm="RSA", purpose="signing", confidence="HIGH", file_path="not-reimported", line_number=2,
                        scanner_ids=["cbom-ingest"], extra={"scan_id":"cbom-ingest:historical"})
    db.add(asset); db.flush(); db.add(SystemAsset(tenant_id="a", system_id=sid, asset_id=asset.id)); db.commit()
    assert ingest(clients["bank_a"]).status_code == 200
    result = reconcile(clients["bank_a"], sid)
    assert result.status_code == 409 and "every historical identity" in result.text
    db.expire_all()
    assert db.query(SystemAsset).filter_by(system_id=sid).count() == 3


def test_commit_failure_is_unconfirmed_not_a_successful_review(banks):
    from api.dependencies import get_db_session
    from db.connection.session import SessionLocal
    from sqlalchemy.exc import SQLAlchemyError
    clients, db, _ = banks
    sid, aid = legacy(db)
    ingest(clients["bank_a"])
    state = detail(clients["bank_a"], sid)
    def failing():
        with SessionLocal() as session:
            def fail():
                raise SQLAlchemyError("injected review commit failure")
            session.commit = fail
            try:
                yield session
            finally:
                session.rollback()
    clients["bank_a"].app.dependency_overrides[get_db_session] = failing
    result = reconcile(clients["bank_a"], sid, state)
    assert result.status_code == 503 and "unconfirmed" in result.text
    db.expire_all()
    assert db.query(SystemAsset).filter_by(system_id=sid, asset_id=aid).count() == 1
    assert "legacy_cbom_disposition" not in db.get(CryptoAsset, aid).extra


def test_audit_failure_rolls_back_review_and_does_not_detach(banks, monkeypatch):
    from db.repositories.user_repository import UserRepository
    clients, db, _ = banks
    sid, aid = legacy(db)
    ingest(clients["bank_a"])
    def fail(*args, **kwargs):
        raise RuntimeError("injected audit failure")
    monkeypatch.setattr(UserRepository, "audit", fail)
    with pytest.raises(RuntimeError, match="injected audit failure"):
        reconcile(clients["bank_a"], sid)
    db.expire_all()
    assert db.query(SystemAsset).filter_by(system_id=sid, asset_id=aid).count() == 1


def test_review_pagination_unassigned_and_tenant_boundaries(banks):
    clients, db, _ = banks
    a_sid, _ = legacy(db)
    legacy(db, tenant="b", name="Other bank secret")
    orphan = CryptoAsset(tenant_id="a", algorithm="AES", confidence="HIGH", file_path="synthetic-only", line_number=0,
                         scanner_ids=["cbom-ingest"])
    db.add(orphan); db.commit()
    response = clients["bank_a"].get("/api/v1/cbom/legacy-imports?page_size=1").json()
    assert response["total"] == 1 and response["systems"][0]["id"] == a_sid
    assert response["unassigned_review_required"] == 1
    assert "Other bank secret" not in str(response)
    assert clients["bank_a"].get("/api/v1/cbom/legacy-imports?page=2&page_size=1").json()["systems"] == []


def test_review_bound_is_explicit_and_applied_in_sql(banks, monkeypatch):
    import api.routers.cbom_legacy as module
    clients, db, _ = banks
    sid, _ = legacy(db)
    monkeypatch.setattr(module, "REVIEW_MAX_ASSETS", 0)
    response = clients["bank_a"].get(f"/api/v1/cbom/system/{sid}/legacy-imports")
    assert response.status_code == 413 and "safety limit" in response.text


def test_import_cannot_refresh_a_genuine_but_old_scan_timestamp(banks):
    from datetime import timedelta
    from db.models.scan import Scan
    clients, db, _ = banks
    sid, _ = legacy(db)
    old_time = datetime.now(timezone.utc) - timedelta(days=180)
    scan = Scan(tenant_id="a", target_location="synthetic-only", scan_start=old_time, status="COMPLETED")
    db.add(scan); db.flush(); db.get(System, sid).last_scan_id = scan.id; db.commit()
    coverage = clients["bank_a"].get("/api/v1/cbom/coverage").json()
    assert coverage["counts"]["CURRENT"] == 0 and coverage["counts"]["STALE"] == 1
    with tenant_scope("a"):
        repo = SystemRepository(db)
        assert repo.list_systems(coverage="CURRENT")[1] == 0
        assert repo.list_systems(coverage="STALE")[1] == 1
        projected = repo.catalog_row(db.get(System, sid))
        assert projected["last_scanned_at"].startswith(old_time.date().isoformat())


def test_evidence_link_added_after_archive_reopens_current_export_block(banks):
    from db.models.scan import Scan
    from db.models.evidence_record import EvidenceRecord
    from db.models.crypto_asset_evidence import CryptoAssetEvidence
    clients, db, _ = banks
    sid, aid = legacy(db)
    ingest(clients["bank_a"])
    assert reconcile(clients["bank_a"], sid).status_code == 200
    scan = Scan(tenant_id="a", target_location="synthetic", scan_start=datetime.now(timezone.utc), status="COMPLETED")
    db.add(scan); db.flush()
    evidence = EvidenceRecord(tenant_id="a",scan_id=scan.id,content_hash="a"*64,chain_hash="b"*64,chain_position=1,
                              file_path="synthetic",line_number=1,finding_data={"synthetic":True})
    db.add(evidence); db.flush(); db.add(CryptoAssetEvidence(tenant_id="a",asset_id=aid,evidence_id=evidence.id)); db.commit()
    assert clients["bank_a"].get("/api/v1/cbom/portfolio").status_code == 409
    assert clients["bank_a"].get("/api/v1/cbom/legacy-imports").json()["unassigned_review_required"] == 1
