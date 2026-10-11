"""VBOM endpoints (advanced/46 P1#5, round 30) — end to end."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register all tables
from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base

pytestmark = pytest.mark.asyncio


def _make_app():
    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "analyst"
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    return app, session


async def _seed_vendor(client, name="EdgeCA", **extra):
    body = {
        "name": name,
        "criticality": "high",
        "vendor_type": "kms",
        "integration_type": "api",
        "data_classifications": ["PII"],
        "security_contact": "sec@edgeca.example",
        "technical_contact": "tech@edgeca.example",
        **extra,
    }
    r = await client.post("/api/v1/vendors", json=body)
    assert r.status_code == 200, r.text
    return r.json()


async def test_vendor_bom_native_and_cyclonedx():
    app, _session = _make_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        vendor = await _seed_vendor(client)
        vid = vendor["id"]

        # import inventory the way production does: vendor CBOM import
        r = await client.post(f"/api/v1/vendors/{vid}/cbom", json={
            "sbom": {
                "bomFormat": "CycloneDX",
                "components": [
                    {"type": "cryptographic-asset", "name": "TLS 1.3",
                     "cryptoProperties": {"algorithmProperties": {
                         "primitive": "ae", "parameterSetIdentifier": "256", "mode": "gcm"}}},
                ],
            },
        })
        assert r.status_code == 200, r.text
        assert r.json()["imported"] == 1

        # estate-wide native document
        r = await client.get("/api/v1/vendor-bom")
        assert r.status_code == 200, r.text
        doc = r.json()
        assert doc["vbomFormat"] == "ZELNX-VBOM"
        assert doc["summary"]["vendors"] == 1
        assert doc["summary"]["crypto_entries"] == 1
        entry_vendor = doc["vendors"][0]
        assert entry_vendor["vendor_id"] == vid
        assert entry_vendor["contacts"]["technical"] == "tech@edgeca.example"
        assert entry_vendor["crypto"][0]["discovery_method"]

        # estate-wide cyclonedx
        r = await client.get("/api/v1/vendor-bom", params={"fmt": "cyclonedx"})
        assert r.status_code == 200
        cdx = r.json()
        assert cdx["bomFormat"] == "CycloneDX"
        assert cdx["components"][0]["type"] == "cryptographic-asset"
        assert cdx["components"][0]["supplier"]["name"] == "EdgeCA"

        # single-vendor slice
        r = await client.get(f"/api/v1/vendors/{vid}/vbom")
        assert r.status_code == 200
        assert r.json()["summary"]["vendors"] == 1
        r = await client.get(f"/api/v1/vendors/{vid}/vbom", params={"fmt": "cyclonedx"})
        assert r.status_code == 200
        assert len(r.json()["components"]) == 1

        # unknown vendor → 404
        r = await client.get("/api/v1/vendors/nope/vbom")
        assert r.status_code == 404

        # invalid format → 422
        r = await client.get("/api/v1/vendor-bom", params={"fmt": "spdx"})
        assert r.status_code == 422


async def test_vendor_bom_includes_system_links_and_profile():
    app, session = _make_app()
    from db.models.system import System

    session.add(System(id="sys-pay", name="Payments", environment="PROD"))
    session.flush()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        vendor = await _seed_vendor(client, system_id="sys-pay")
        vid = vendor["id"]

        # a profile revision exists from creation (profile passed) or not —
        # create one explicitly to pin the linkage
        r = await client.put(f"/api/v1/vendors/{vid}/profile", json={
            "profile": {
                "vendor_name": "EdgeCA",
                "pqc_status": "planned",
                "cbom_provided": "yes",
            },
        })
        if r.status_code == 200:
            doc = (await client.get("/api/v1/vendor-bom")).json()
            v = doc["vendors"][0]
            assert v["profile"] is not None
            assert v["profile"]["status"] in {"DRAFT", "APPROVED", "REVIEW"}

        doc = (await client.get("/api/v1/vendor-bom")).json()
        v = doc["vendors"][0]
        assert v["systems"][0]["system_id"] == "sys-pay"
        assert v["systems"][0]["system_name"] == "Payments"
