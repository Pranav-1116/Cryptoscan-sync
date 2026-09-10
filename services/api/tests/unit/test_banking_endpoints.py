"""Banking & Regulatory API endpoints.

Same fixture pattern as the technology-BOM endpoint tests: in-memory SQLite via
the app_db fixture, ASGITransport + AsyncClient, real materialization path.
"""

from __future__ import annotations

import db.models  # noqa: F401 — register all tables
import pytest
from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base
from db.models import CryptoAsset, HardwareAsset
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


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
    application.state.test_session = session

    session.add_all([
        CryptoAsset(id="ca-rsa", algorithm="RSA", file_path="src/Pay.java",
                    purpose="key_exchange", key_size=2048, confidence=1.0),
        CryptoAsset(id="ca-aes", algorithm="AES", file_path="src/Store.java",
                    purpose="encryption", key_size=256, confidence=1.0),
        HardwareAsset(id="hw-hsm-1", asset_id="HSM-0001", manufacturer="Thales",
                      model="Luna Network HSM", device_type="hsm",
                      firmware={"version": "7.8.9"},
                      hsm={"algorithms": ["ML-KEM"]}),
    ])
    session.commit()

    yield application

    application.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_banking_overview_returns_regulatory_surface(app_db):
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://test") as client:
        resp = await client.get("/api/v1/banking/overview")
    assert resp.status_code == 200
    body = resp.json()
    assert body["source"] == "technology_bom"
    ov = body["overview"]
    assert ov["hndl"]["at_risk"] is True          # RSA-2048 key exchange
    assert ov["hsm"]["total"] == 1
    assert ov["hsm"]["pqc_ready"] == 1            # declares ML-KEM
    assert ov["roadmap"]["total_in_scope"] >= 1


@pytest.mark.asyncio
async def test_banking_action_plan_frameworks(app_db):
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://test") as client:
        ecb = await client.get("/api/v1/banking/action-plan?framework=ecb&institution=Test%20Bank")
        generic = await client.get("/api/v1/banking/action-plan")
        bad = await client.get("/api/v1/banking/action-plan?framework=madeup")
    assert ecb.status_code == 200 and generic.status_code == 200
    assert bad.status_code == 422
    ecb_body = ecb.json()
    assert ecb_body["framework"] == "ecb"
    assert ecb_body["institution"] == "Test Bank"
    assert any("ECB" in ref for ref in ecb_body["references"])
    assert ecb_body["evidence"]["snapshot_id"]
    assert ecb_body["assessment"]["admission"]["decision"] in ("PASS", "WARN", "FAIL")
    assert isinstance(ecb_body["phases"], list) and len(ecb_body["phases"]) == 4
    assert isinstance(ecb_body["hndl_register"], list)


@pytest.mark.asyncio
async def test_banking_hndl_and_roadmap_endpoints(app_db):
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://test") as client:
        hndl = await client.get("/api/v1/banking/hndl")
        roadmap = await client.get("/api/v1/banking/roadmap")
    assert hndl.status_code == 200
    assert hndl.json()["total"] == 1  # RSA-2048 key exchange only
    entry = hndl.json()["entries"][0]
    assert entry["deadline"] == 2030 and entry["exposure"] == "critical"
    assert roadmap.status_code == 200
    phases = {p["phase"] for p in roadmap.json()["phases"]}
    assert phases == {"P1", "P2", "P3", "P4"}


@pytest.mark.asyncio
async def test_banking_hsm_fleet_endpoint(app_db):
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://test") as client:
        resp = await client.get("/api/v1/banking/hsm")
    assert resp.status_code == 200
    fleet = resp.json()["fleet"]
    assert fleet["total"] == 1 and fleet["pqc_ready"] == 1
    assert fleet["hsms"][0]["fips"]["status"] == "validated"  # Thales Luna family


RACDCERT = """Digital certificate information for site certificate PAYGW:
    Status: TRUST
    Expiration Date: 2027/01/01 00:00:00
    Certificate Key Size: 2048
    Algorithm Signature: SHA256WithRSA
    Subject: CN=paygw.bank
"""


@pytest.mark.asyncio
async def test_mainframe_ingest_persists_into_unified_inventory(app_db):
    async with AsyncClient(transport=ASGITransport(app=app_db), base_url="http://test") as client:
        first = await client.post("/api/v1/banking/mainframe/ingest", json={
            "kind": "racdcert", "content": RACDCERT})
        again = await client.post("/api/v1/banking/mainframe/ingest", json={
            "kind": "racdcert", "content": RACDCERT})
        inv = await client.get("/api/v1/banking/mainframe")
        bad = await client.post("/api/v1/banking/mainframe/ingest", json={
            "kind": "nonsense", "content": "x"})
    assert first.status_code == 200 and again.status_code == 200
    assert first.json()["inserted"] == 1
    assert again.json()["duplicates"] == 1 and again.json()["inserted"] == 0  # idempotent
    assert bad.status_code == 422
    body = inv.json()
    assert body["total"] == 1 and body["by_source"] == {"zos-racf": 1}
    asset = body["assets"][0]
    assert asset["algorithm"] == "RSA" and asset["key_size"] == 2048
    assert asset["quantum"]["transition"] in ("deprecated_after_2030", "disallowed_after_2035")

    # the ingest must be visible in the UNIFIED BOM (same crypto_assets table)
    session = app_db.state.test_session
    rows = list(session.query(CryptoAsset).filter(
        CryptoAsset.source_language == "zos-racf").all())
    assert len(rows) == 1 and rows[0].file_path == "racf://PAYGW"
