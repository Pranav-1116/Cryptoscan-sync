"""Intelligence router endpoint tests — evidence pack, agility, work-orders,
gate, materials, quantum, transfer import/export (previously untested)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register all tables
from api.dependencies import get_current_user, get_db_session, require_auditor
from api.main import create_app
from db.connection.session import Base
from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan


def _make_app():
    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:",
                           connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "intel-tester"
    app.dependency_overrides[require_auditor] = lambda: "intel-auditor"
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    return app, session


def _seed(session, *, scan_id: str = "scan-1", algorithm: str = "DES"):
    session.add(Scan(
        id=scan_id, scan_start=datetime(2026, 8, 29, tzinfo=timezone.utc),
        target_location="https://github.com/org/legacy.git",
        target_type="GIT_REPOSITORY", status="COMPLETED", statistics={},
    ))
    session.add(EvidenceRecord(
        scan_id=scan_id, content_hash="c" * 64, chain_hash="",
        chain_position=0, previous_hash=None, algorithm=algorithm,
        confidence="HIGH", purpose="ENCRYPTION", mode="CBC", key_size=56,
        file_path="src/Pay.java", line_number=7,
        finding_data={"scanner_id": "s", "metadata": {}},
        compliance_status="FAIL",
    ))
    session.flush()


class _AppClient:
    """AsyncClient wrapper that also exposes the test DB session."""

    def __init__(self, client: AsyncClient, session):
        self.client = client
        self.session = session

    async def get(self, *args, **kwargs):
        return await self.client.get(*args, **kwargs)

    async def post(self, *args, **kwargs):
        return await self.client.post(*args, **kwargs)


@pytest.fixture
def app_client():
    app, session = _make_app()
    _seed(session)
    transport = ASGITransport(app=app)
    yield _AppClient(AsyncClient(transport=transport, base_url="http://test"), session)
    session.close()


@pytest.mark.asyncio
async def test_evidence_pack_download(app_client):
    response = await app_client.get("/api/v1/scans/scan-1/evidence-pack")
    assert response.status_code == 200
    assert response.headers["content-disposition"].startswith("attachment")
    body = response.json()
    assert body["pack_format"] == "cryptoscan-evidence-pack"
    assert "records" in body


@pytest.mark.asyncio
async def test_evidence_pack_missing_scan_404(app_client):
    response = await app_client.get("/api/v1/scans/nope/evidence-pack")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_verify_pack_round_trip(app_client):
    # build a real pack via the endpoint, then verify it via /verify
    pack = (await app_client.get(
        "/api/v1/scans/scan-1/evidence-pack")).json()
    response = await app_client.post(
        "/api/v1/evidence-pack/verify", json={"pack": pack})
    assert response.status_code == 200
    verification = response.json()
    assert verification["result"] == "PASS"
    assert verification["chain_intact"] is True


@pytest.mark.asyncio
async def test_agility_and_work_orders(app_client):
    agility = await app_client.get("/api/v1/scans/scan-1/agility")
    assert agility.status_code == 200
    assert "score" in agility.json() or "factors" in agility.json()

    orders = await app_client.get("/api/v1/scans/scan-1/work-orders")
    assert orders.status_code == 200
    assert isinstance(orders.json(), (dict, list))


@pytest.mark.asyncio
async def test_gate_and_sarif(app_client):
    gate = await app_client.get("/api/v1/scans/scan-1/gate")
    assert gate.status_code == 200
    body = gate.json()
    assert "decision" in body
    assert "sarif" in body

    sarif = await app_client.get("/api/v1/scans/scan-1/gate.sarif")
    assert sarif.status_code == 200
    sarif_body = sarif.json()
    assert sarif_body["version"] == "2.1.0"


@pytest.mark.asyncio
async def test_materials(app_client):
    response = await app_client.get("/api/v1/scans/scan-1/materials")
    assert response.status_code == 200
    assert "count" in response.json()


@pytest.mark.asyncio
async def test_quantum_risk(app_client):
    response = await app_client.get("/api/v1/scans/scan-1/quantum")
    assert response.status_code == 200
    assert isinstance(response.json(), dict)


@pytest.mark.asyncio
async def test_audit_pack_zip(app_client):
    response = await app_client.get("/api/v1/scans/scan-1/audit-pack")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    assert response.content[:2] == b"PK"


@pytest.mark.asyncio
async def test_transfer_export_and_import_round_trip(app_client):
    exported = await app_client.get("/api/v1/scans/scan-1/transfer")
    assert exported.status_code == 200
    payload = exported.json()
    assert payload["transfer_format"] == "cryptoscan-scan-transfer"
    assert payload["digests"]["payload_digest"]
    assert payload["digests"]["records_digest"]

    # simulate a fresh instance: remove the scan, then import the payload
    scan = app_client.session.get(Scan, "scan-1")
    app_client.session.delete(scan)
    app_client.session.commit()

    imported = await app_client.post("/api/v1/scans/import",
                                     json=payload)
    assert imported.status_code == 200
    body = imported.json()
    assert body["imported"] is True
    assert body["records"] >= 1

    # second import is idempotent — never duplicates
    again = await app_client.post("/api/v1/scans/import", json=payload)
    assert again.json()["imported"] is False


@pytest.mark.asyncio
async def test_import_rejects_tampered_payload(app_client):
    payload = (await app_client.get(
        "/api/v1/scans/scan-1/transfer")).json()
    payload["records"][0]["algorithm"] = "TAMPERED"
    response = await app_client.post("/api/v1/scans/import",
                                     json=payload)
    assert response.status_code == 400
