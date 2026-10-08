"""A scan verification verdict must cover stored payloads and completeness."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401
from api.config.settings import get_settings
from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base
from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan
from evidence.core.pipeline import EvidencePipeline


@pytest.fixture()
def scan_client(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "auditor"
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    with TestClient(app) as client:
        yield client, session
    session.close()
    engine.dispose()


def _seed(session, *, empty=False):
    scan_id = "scan-verification"
    finding = {"finding_id": "f1", "source": {"file_path": "Pay.java", "line_number": 3},
               "crypto": {"algorithm": "AES"}, "metadata": {"confidence": "HIGH"}}
    records, manifest = EvidencePipeline(scan_id).process([] if empty else [finding], scan_id=scan_id)
    session.add(Scan(id=scan_id, status="COMPLETED", target_location="local://fixture",
                     scan_start=datetime.now(timezone.utc),
                     manifest_hash=manifest.manifest_hash,
                     statistics={"total_findings": len(records)}))
    session.flush()
    for record in records:
        session.add(EvidenceRecord(
            id=record.evidence_id, scan_id=scan_id, content_hash=record.content_hash,
            chain_hash=record.chain_hash, previous_hash=record.previous_hash,
            chain_position=record.chain_position, finding_data=record.finding,
            algorithm="AES", confidence="HIGH", file_path="Pay.java", line_number=3,
        ))
    session.commit()
    return scan_id


def test_verify_recomputes_payload_chain_and_manifest(scan_client):
    client, session = scan_client
    scan_id = _seed(session)
    response = client.get(f"/api/v1/scans/{scan_id}/verify")
    assert response.status_code == 200
    assert response.json()["result"] == "PASS"
    assert response.json()["content_intact"] is True
    assert response.json()["manifest_intact"] is True

    row = session.query(EvidenceRecord).first()
    row.finding_data = {**row.finding_data, "crypto": {"algorithm": "DES"}}
    session.commit()
    tampered = client.get(f"/api/v1/scans/{scan_id}/verify").json()
    assert tampered["result"] == "FAIL"
    assert tampered["content_intact"] is False


def test_verify_detects_missing_records_in_a_completed_scan(scan_client):
    client, session = scan_client
    scan_id = _seed(session)
    session.query(EvidenceRecord).delete()
    session.commit()
    verdict = client.get(f"/api/v1/scans/{scan_id}/verify").json()
    assert verdict["result"] == "FAIL"
    assert verdict["manifest_intact"] is False


def test_verify_distinguishes_empty_scan_from_missing_manifest(scan_client):
    client, session = scan_client
    scan_id = _seed(session, empty=True)
    verdict = client.get(f"/api/v1/scans/{scan_id}/verify").json()
    assert verdict["result"] == "EMPTY"
    assert verdict["manifest_hash"] == hashlib.sha256(b"").hexdigest()

    scan = session.get(Scan, scan_id)
    scan.manifest_hash = None
    session.commit()
    unknown = client.get(f"/api/v1/scans/{scan_id}/verify").json()
    assert unknown["result"] == "UNVERIFIABLE"
