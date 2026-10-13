"""Persisted, content-addressed CBOM snapshots (§4.4, round 45).

The live scan-CBOM route regenerates from current evidence on every call;
a snapshot pins ONE deterministic rendering, content-addressed by SHA-256,
served verbatim with an integrity self-check. Creation is idempotent;
tampering with the stored payload is detected, never served as trusted.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register tables
from api.dependencies import get_current_user, get_db_session, require_auditor
from api.main import create_app
from db.connection.session import Base
from db.models.cbom_snapshot import CbomSnapshot
from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan

NOW = datetime(2026, 10, 13, tzinfo=timezone.utc)


def _make_app():
    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "cbom-snapshots-" + "z" * 21)
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "auditor"
    app.dependency_overrides[require_auditor] = lambda: "auditor"
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    return app, session, engine


def _seed(session, scan_id: str = "scan-snap-1") -> None:
    session.add(Scan(id=scan_id, status="COMPLETED", target_type="GIT_REPOSITORY",
                     target_location="https://github.com/acme/payments.git",
                     target_branch="main", scan_start=NOW, scan_end=NOW))
    for i, algorithm in enumerate(("RSA-2048", "AES-256-GCM")):
        session.add(EvidenceRecord(
            id=f"ev-{scan_id}-{i}", scan_id=scan_id, algorithm=algorithm,
            compliance_status="PASS", file_path=f"src/F{i}.java", line_number=i + 1,
            purpose="ENCRYPTION", content_hash=f"c{i}" * 32, chain_hash=f"h{i}" * 32,
            chain_position=i, confidence="HIGH", finding_data={},
        ))
    session.commit()


@pytest.mark.asyncio
async def test_snapshot_pins_the_document_and_serves_it_verbatim():
    app, session, engine = _make_app()
    _seed(session)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        created = await c.post("/api/v1/cbom/scan/scan-snap-1/snapshot")
        assert created.status_code == 200, created.text
        body = created.json()
        assert body["created"] is True
        assert len(body["content_hash"]) == 64
        assert body["component_count"] == 2
        assert body["verify_path"] == f"/api/v1/cbom/snapshots/{body['snapshot_id']}"

        served = await c.get(body["verify_path"])
        assert served.status_code == 200
        doc = served.json()
        assert doc["integrity"] == "OK"
        assert doc["scan_id"] == "scan-snap-1"
        assert doc["scan_verify_path"] == "/api/v1/scans/scan-snap-1/verify"
        # the exact pinned document: components as rendered at pin time
        assert doc["payload"]["components"], "pinned payload carries the components"
        # provenance back to the exact scan (CycloneDX externalReferences)
        assert {"type": "provenance",
                "url": "urn:cryptoscan:scan:scan-snap-1"} in doc["payload"]["externalReferences"]
    engine.dispose()


@pytest.mark.asyncio
async def test_identical_rendering_collapses_to_one_snapshot():
    app, session, engine = _make_app()
    _seed(session)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        first = (await c.post("/api/v1/cbom/scan/scan-snap-1/snapshot")).json()
        second = (await c.post("/api/v1/cbom/scan/scan-snap-1/snapshot")).json()
    assert second["created"] is False
    assert second["snapshot_id"] == first["snapshot_id"]
    assert "already pinned" in second["note"]
    rows = session.query(CbomSnapshot).all()
    assert len(rows) == 1, "content-addressed: same rendering, one row"
    engine.dispose()


@pytest.mark.asyncio
async def test_evidence_change_creates_a_new_snapshot_not_a_silent_rewrite():
    app, session, engine = _make_app()
    _seed(session)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        first = (await c.post("/api/v1/cbom/scan/scan-snap-1/snapshot")).json()
        # a third finding appears after the pin
        session.add(EvidenceRecord(
            id="ev-snap-new", scan_id="scan-snap-1", algorithm="ECDSA-P256",
            compliance_status="PASS", file_path="src/New.java", line_number=1,
            purpose="SIGNATURE", content_hash="n" * 64, chain_hash="m" * 64,
            chain_position=2, confidence="HIGH", finding_data={},
        ))
        session.commit()
        second = (await c.post("/api/v1/cbom/scan/scan-snap-1/snapshot")).json()
    assert second["created"] is True
    assert second["snapshot_id"] != first["snapshot_id"]
    assert second["component_count"] == first["component_count"] + 1
    assert second["content_hash"] != first["content_hash"]
    # the first snapshot still serves its ORIGINAL rendering
    served = (await AsyncClient(transport=ASGITransport(app=app), base_url="http://t")
              .get(f"/api/v1/cbom/snapshots/{first['snapshot_id']}")).json()
    assert served["integrity"] == "OK"
    assert served["component_count"] == first["component_count"]
    engine.dispose()


@pytest.mark.asyncio
async def test_tampered_payload_is_detected_not_served_as_trusted():
    app, session, engine = _make_app()
    _seed(session)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        created = (await c.post("/api/v1/cbom/scan/scan-snap-1/snapshot")).json()
    # direct DB tampering after the pin
    row = session.query(CbomSnapshot).filter_by(id=created["snapshot_id"]).one()
    row.payload = dict(row.payload, components=[])
    session.commit()

    served = (await AsyncClient(transport=ASGITransport(app=app), base_url="http://t")
              .get(f"/api/v1/cbom/snapshots/{created['snapshot_id']}")).json()
    assert served["integrity"] == "MISMATCH"
    assert "Do not trust it" in served["integrity_note"]
    engine.dispose()


@pytest.mark.asyncio
async def test_snapshots_are_listed_per_scan_with_the_regeneration_caveat():
    app, session, engine = _make_app()
    _seed(session)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        await c.post("/api/v1/cbom/scan/scan-snap-1/snapshot")
        listed = await c.get("/api/v1/cbom/scan/scan-snap-1/snapshots")
    assert listed.status_code == 200
    body = listed.json()
    assert body["count"] == 1
    assert body["snapshots"][0]["generator"] == "api"
    assert "may differ" in body["note"]
    # unknown scan is a honest 404, not an empty list
    missing = (await AsyncClient(transport=ASGITransport(app=app), base_url="http://t")
               .get("/api/v1/cbom/scan/nope/snapshots"))
    assert missing.status_code == 404
    engine.dispose()


@pytest.mark.asyncio
async def test_unknown_snapshot_is_404():
    app, _session, engine = _make_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get("/api/v1/cbom/snapshots/does-not-exist")
    assert r.status_code == 404
    engine.dispose()
