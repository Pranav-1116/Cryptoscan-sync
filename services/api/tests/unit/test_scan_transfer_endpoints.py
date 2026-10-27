"""Scan transfer endpoints: export from one instance, verify + import into another."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

import db.models  # noqa: F401 — register all tables
from api.dependencies import get_current_user, get_db_session, require_auditor
from api.main import create_app
from db.connection.session import Base
from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan


def _make_app():
    from sqlalchemy.pool import StaticPool

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    session = Session()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "testuser"
    app.dependency_overrides[require_auditor] = lambda: "auditor-user"
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    return app, session, engine


def _seed(session):
    session.add(
        Scan(
            id="scan-zone-a",
            scan_start=datetime(2026, 8, 28, 10, 0, 0, tzinfo=timezone.utc),
            target_location="https://gitlab.zone-a.bank/core.git",
            target_type="GIT_REPOSITORY",
            status="COMPLETED",
            statistics={"total_findings": 2},
        )
    )
    session.add_all(
        [
            EvidenceRecord(
                scan_id="scan-zone-a", content_hash="a" * 64, chain_hash="h0" + "0" * 62,
                chain_position=0, previous_hash=None, algorithm="RSA-2048", confidence="HIGH",
                file_path="src/Pay.java", line_number=7, finding_data={"scanner_id": "s"},
                compliance_status="FAIL",
            ),
            EvidenceRecord(
                scan_id="scan-zone-a", content_hash="b" * 64, chain_hash="h1" + "1" * 62,
                chain_position=1, previous_hash="h0" + "0" * 62, algorithm="AES-256", confidence="HIGH",
                file_path="src/Seal.java", line_number=9, finding_data={"scanner_id": "s"},
                compliance_status="PASS",
            ),
        ]
    )
    session.flush()


@pytest.mark.asyncio
async def test_export_then_import_into_fresh_instance():
    app_a, session_a, engine_a = _make_app()
    _seed(session_a)

    transport = ASGITransport(app=app_a)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/scans/scan-zone-a/transfer")
    assert response.status_code == 200
    payload = response.json()
    assert payload["transfer_format"] == "cryptoscan-scan-transfer"
    assert payload["digests"]["record_count"] == 2

    app_b, session_b, engine_b = _make_app()  # a completely separate instance
    transport_b = ASGITransport(app=app_b)
    async with AsyncClient(transport=transport_b, base_url="http://test") as client:
        imported = await client.post("/api/v1/scans/import", json=payload)
    assert imported.status_code == 200
    body = imported.json()
    assert body["imported"] is True and body["records"] == 2

    scan = session_b.get(Scan, "scan-zone-a")
    assert scan is not None and scan.target_location == "https://gitlab.zone-a.bank/core.git"
    from shared_models.chrono import aware

    assert scan.scan_start is not None and aware(scan.scan_start) is not None
    assert aware(scan.scan_start).tzinfo is not None  # naive per SQLite driver; chrono re-awares
    records = list(session_b.execute(select(EvidenceRecord).where(EvidenceRecord.scan_id == "scan-zone-a")).scalars())
    assert len(records) == 2
    assert {row.algorithm for row in records} == {"RSA-2048", "AES-256"}
    assert records[0].policy_evaluation is not None or records[0].finding_data == {"scanner_id": "s"}

    # idempotent re-import: reported, never duplicated
    async with AsyncClient(transport=transport_b, base_url="http://test") as client:
        again = await client.post("/api/v1/scans/import", json=payload)
    assert again.status_code == 200
    assert again.json()["imported"] is False and again.json()["reason"] == "scan_already_present"
    assert len(list(session_b.execute(select(EvidenceRecord).where(EvidenceRecord.scan_id == "scan-zone-a")).scalars())) == 2

    session_a.close(); engine_a.dispose()
    session_b.close(); engine_b.dispose()


@pytest.mark.asyncio
async def test_tampered_transfer_rejected_with_errors():
    app_a, session_a, engine_a = _make_app()
    _seed(session_a)
    transport = ASGITransport(app=app_a)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = (await client.get("/api/v1/scans/scan-zone-a/transfer")).json()
    session_a.close(); engine_a.dispose()

    payload["records"][0]["algorithm"] = "AES-256-GCM"  # modified in transit

    app_b, session_b, engine_b = _make_app()
    transport_b = ASGITransport(app=app_b)
    async with AsyncClient(transport=transport_b, base_url="http://test") as client:
        rejected = await client.post("/api/v1/scans/import", json=payload)
    assert rejected.status_code == 400
    detail = rejected.json()["detail"]
    assert any("mismatch" in error for error in detail["errors"])
    assert session_b.get(Scan, "scan-zone-a") is None  # nothing persisted
    session_b.close(); engine_b.dispose()


@pytest.mark.asyncio
async def test_export_unknown_scan_404():
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/scans/ghost/transfer")
    assert response.status_code == 404
    session.close(); engine.dispose()
