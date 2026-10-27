"""Round 25 (deep/25 §3.5, P1#5): reverse evidence lookup.

Forward direction existed (every CBOM component's evidence block carries
content_hash/chain_hash); the reverse — a hash observed in a downloaded
BOM → the scans and components that cite it — did not. Deterministic; no
network.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import db.models  # noqa: F401 — register tables
from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base
from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan

NOW = datetime(2026, 10, 10, 12, 0, 0, tzinfo=timezone.utc)
HASH = "ab" * 32


@pytest.fixture()
def app_db():
    from sqlalchemy.pool import StaticPool

    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    session = Session()

    application = create_app()
    application.dependency_overrides[get_current_user] = lambda: "testuser"

    def _session():
        yield session

    application.dependency_overrides[get_db_session] = _session
    return application, session


def _evidence(session, evidence_id, scan_id, content_hash, *, chain_position=0,
              deleted=False, algorithm="RSA-2048"):
    row = EvidenceRecord(
        id=evidence_id, scan_id=scan_id, content_hash=content_hash,
        chain_hash="c" * 64, chain_position=chain_position, algorithm=algorithm,
        key_size=2048, confidence="HIGH", file_path="src/Pay.java", line_number=42,
        compliance_status="FAIL", finding_data={},
    )
    if deleted:
        row.deleted_at = NOW
        row.deleted_by = "auditor"
    session.add(row)
    return row


@pytest.mark.anyio
async def test_reverse_lookup_finds_components_across_scans(app_db):
    app, session = app_db
    session.add_all(
        [
            Scan(id="scan-1", scan_start=NOW, target_location="repo-A", status="COMPLETED"),
            Scan(id="scan-2", scan_start=NOW, target_location="repo-B", status="COMPLETED"),
        ]
    )
    # the same observed fact, recorded by two scans
    _evidence(session, "ev-1", "scan-1", HASH)
    _evidence(session, "ev-2", "scan-2", HASH)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get(f"/api/v1/cbom/evidence/{HASH}")

    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 2
    assert body["truncated"] is False
    assert {c["scan_id"] for c in body["components"]} == {"scan-1", "scan-2"}
    first = body["components"][0]
    assert first["cbom_url"] == f"/api/v1/cbom/scan/{first['scan_id']}"
    assert first["algorithm"] == "RSA-2048"
    assert first["chain_hash"] == "c" * 64
    assert first["compliance_status"] == "FAIL"


@pytest.mark.anyio
async def test_retracted_evidence_is_not_a_component(app_db):
    app, session = app_db
    session.add(Scan(id="scan-1", scan_start=NOW, target_location="repo-A", status="COMPLETED"))
    _evidence(session, "ev-alive", "scan-1", HASH)
    _evidence(session, "ev-retracted", "scan-1", "ef" * 32, deleted=True)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        alive = await client.get(f"/api/v1/cbom/evidence/{HASH}")
        retracted = await client.get(f"/api/v1/cbom/evidence/{'ef' * 32}")

    assert alive.json()["count"] == 1
    assert retracted.json() == {
        "content_hash": "ef" * 32, "count": 0, "truncated": False, "components": [],
    }


@pytest.mark.anyio
async def test_invalid_hash_is_rejected_and_unknown_is_zero(app_db):
    app, _session = app_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        bad = await client.get("/api/v1/cbom/evidence/not-a-hash")
        unknown = await client.get(f"/api/v1/cbom/evidence/{'00' * 32}")

    assert bad.status_code == 422
    assert unknown.status_code == 200
    assert unknown.json()["count"] == 0
