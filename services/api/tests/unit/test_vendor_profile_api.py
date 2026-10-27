"""API lifecycle tests for versioned vendor due-diligence profiles."""
from __future__ import annotations

import os

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401
from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base


def _make_app():
    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "vendor-reviewer"

    def _session():
        yield session

    app.dependency_overrides[get_db_session] = _session
    return app


@pytest.mark.asyncio
async def test_vendor_profile_schema_empty_state_and_draft_history():
    app = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        vendor = (await client.post("/api/v1/vendors", json={"name": "ProfileVendor"})).json()
        vendor_id = vendor["id"]
        schema = await client.get(f"/api/v1/vendors/{vendor_id}/profile/schema")
        empty = await client.get(f"/api/v1/vendors/{vendor_id}/profile")
        profile = empty.json()["profile"]
        validated = await client.post(
            f"/api/v1/vendors/{vendor_id}/profile/validate",
            json={"profile": profile},
        )
        saved = await client.put(
            f"/api/v1/vendors/{vendor_id}/profile",
            json={"profile": profile, "status": "DRAFT", "source": "api-test"},
        )
        history = await client.get(f"/api/v1/vendors/{vendor_id}/profile/history")

    assert schema.status_code == 200
    assert schema.json()["properties"]["schema"]["default"] == "cryptoscan.vendor-profile/1"
    assert empty.status_code == 200
    assert empty.json()["persisted"] is False
    assert empty.json()["completeness"]["status"] == "INCOMPLETE"
    assert validated.status_code == 200
    assert validated.json()["valid"] is True
    assert saved.status_code == 200
    assert saved.json()["revision"] == 1
    assert saved.json()["status"] == "DRAFT"
    assert history.status_code == 200
    assert len(history.json()["revisions"]) == 1


@pytest.mark.asyncio
async def test_vendor_profile_rejects_secrets_and_unverified_approval():
    app = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        vendor = (await client.post("/api/v1/vendors", json={"name": "ApprovalVendor"})).json()
        vendor_id = vendor["id"]
        secret = await client.post(
            f"/api/v1/vendors/{vendor_id}/profile/validate",
            json={"profile": {"identity": {"legal_name": "ApprovalVendor", "password": "no"}}},
        )
        profile = (await client.get(f"/api/v1/vendors/{vendor_id}/profile")).json()["profile"]
        approval = await client.put(
            f"/api/v1/vendors/{vendor_id}/profile",
            json={
                "profile": profile,
                "status": "APPROVED",
                "reviewed_by": "vendor-reviewer",
            },
        )

    assert secret.status_code == 422
    assert "secret" in str(secret.json()).lower()
    assert approval.status_code == 422
    assert "approval_issues" in approval.json()["detail"]


@pytest.mark.asyncio
async def test_vendor_profile_evidence_expiration_and_risk_preserve_audit_history():
    app = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        vendor = (await client.post("/api/v1/vendors", json={"name": "EvidenceVendor"})).json()
        vendor_id = vendor["id"]
        profile = (await client.get(f"/api/v1/vendors/{vendor_id}/profile")).json()["profile"]
        await client.put(
            f"/api/v1/vendors/{vendor_id}/profile",
            json={"profile": profile, "status": "DRAFT"},
        )
        evidence = await client.post(
            f"/api/v1/vendors/{vendor_id}/profile/evidence",
            json={
                "evidence_id": "contract-1",
                "evidence_type": "CONTRACT",
                "evidence_reference": "doc://vendor/contract-1",
                "status": "UNVERIFIED",
                "redaction_status": "VERIFIED_NO_SECRETS",
            },
        )
        risk = await client.get(f"/api/v1/vendors/{vendor_id}/risk")
        expired = await client.delete(f"/api/v1/vendors/{vendor_id}/profile?reason=contract-replaced")
        history = await client.get(f"/api/v1/vendors/{vendor_id}/profile/history")
        current = await client.get(f"/api/v1/vendors/{vendor_id}/profile")

    assert evidence.status_code == 200
    assert evidence.json()["evidence_id"] == "contract-1"
    assert risk.status_code == 200
    assert "due_diligence" in risk.json()
    assert expired.status_code == 200
    assert expired.json()["status"] == "EXPIRED"
    assert expired.json()["audit_preserved"] is True
    assert len(history.json()["revisions"]) == 3
    assert current.json()["status"] == "EXPIRED"
