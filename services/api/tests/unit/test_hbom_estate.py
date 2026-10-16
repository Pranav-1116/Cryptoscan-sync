"""The independent estate HBOM surface (§4.4, round 71).

``GET /api/v1/hbom`` regenerates ONE unified document over every
persisted ``hardware_assets`` row (per-asset identity, posture, evidence
references, deterministic content hash); ``POST /hbom/snapshot`` pins it
content-addressed (identical renderings collapse); ``GET
/hbom/snapshots/{id}`` serves the exact stored document verbatim with an
integrity self-check. Mirrors the pinning discipline pinned by the CBOM
(round 45) and report (round 69) suites.
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
from db.models.hardware_live import HardwareAsset
from db.models.hbom_snapshot import HbomSnapshot

NOW = datetime(2026, 10, 15, tzinfo=timezone.utc)
LATER = datetime(2026, 10, 16, tzinfo=timezone.utc)


def _make_app():
    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "hbom-estate-" + "z" * 21)
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


def _seed_hsm(session) -> None:
    session.add(HardwareAsset(
        asset_id="hw-hsm-1", agent_id="agent-dc-1",
        manufacturer="Utimaco", model="CryptoServer", device_type="hsm",
        serial_reference="SER-0001", hardware_revision="C",
        current_fingerprint="f" * 64, previous_fingerprint="e" * 64,
        first_seen=NOW, last_seen=NOW, last_verified=NOW,
        last_firmware_check=NOW, last_crypto_check=NOW, last_change="firmware",
        firmware={"version": "4.21.2"}, tpm=None, hsm={"fips_mode": True},
        capabilities={"rng": True}, crypto_capabilities={"rsa": [2048, 4096]},
        evidence_history=["ev-h1", "ev-h2"], risk_score=40, risk_level="MEDIUM",
    ))
    session.commit()


def _seed_tpm(session, *, last_seen=LATER) -> None:
    session.add(HardwareAsset(
        asset_id="hw-tpm-1", agent_id="agent-branch-7",
        manufacturer="Infineon", model="SLB9665", device_type="tpm",
        current_fingerprint="a" * 64,
        first_seen=NOW, last_seen=last_seen,
        firmware=None, tpm={"spec": "2.0"}, hsm=None,
        evidence_history=["ev-t1"], risk_score=10, risk_level="LOW",
    ))
    session.commit()


@pytest.mark.asyncio
async def test_empty_estate_is_honest_not_fabricated():
    app, session, engine = _make_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get("/api/v1/hbom")
        assert r.status_code == 200, r.text
        doc = r.json()
        assert doc["components"] == []
        assert doc["metadata"]["component_count"] == 0
        assert doc["metadata"]["as_of"] is None
        assert "empty, not fabricated" in " ".join(doc["metadata"]["notes"])
        assert len(doc["content_hash"]) == 64
    engine.dispose()


@pytest.mark.asyncio
async def test_estate_document_carries_identity_and_evidence():
    app, session, engine = _make_app()
    _seed_hsm(session)
    _seed_tpm(session)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        first = await c.get("/api/v1/hbom")
        assert first.status_code == 200, first.text
        doc = first.json()
        refs = [comp["bom-ref"] for comp in doc["components"]]
        assert refs == ["hw:hw-hsm-1", "hw:hw-tpm-1"]

        hsm = doc["components"][0]
        assert hsm["name"] == "Utimaco CryptoServer"
        assert hsm["identity"]["serial_reference"] == "SER-0001"
        assert hsm["security_modules"] == {"hsm": {"fips_mode": True}}
        assert hsm["firmware"]["details"] == {"version": "4.21.2"}
        assert hsm["evidence"]["source"].startswith("live hardware inventory")
        assert hsm["evidence"]["agent_id"] == "agent-dc-1"
        assert hsm["evidence"]["evidence_ids"] == ["ev-h1", "ev-h2"]
        assert hsm["evidence"]["last_seen"] == NOW.isoformat()

        # unified: both agents' devices in ONE document, fleet-aggregated
        assert doc["metadata"]["component_count"] == 2
        assert doc["hsm_fleet"]["asset_ids"] == ["hw-hsm-1"]
        assert doc["tpm_fleet"]["asset_ids"] == ["hw-tpm-1"]
        # anchored to the estate's latest observation, deterministic re-GET
        assert doc["metadata"]["as_of"] == LATER.isoformat()
        again = await c.get("/api/v1/hbom")
        assert again.json() == doc
    engine.dispose()


@pytest.mark.asyncio
async def test_cyclonedx_format_serves_the_same_estate():
    app, session, engine = _make_app()
    _seed_hsm(session)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.get("/api/v1/hbom", params={"fmt": "cyclonedx"})
        assert r.status_code == 200, r.text
        cd = r.json()
        assert cd["bomFormat"] == "CycloneDX"
        assert cd["specVersion"] == "1.5"
        # timestamp is the document's own anchor, not a wall clock
        assert cd["metadata"]["timestamp"] == NOW.isoformat()
        (comp,) = cd["components"]
        assert comp["type"] == "device"
        assert comp["version"] == "4.21.2"
        props = {p["name"]: p["value"] for p in comp["properties"]}
        assert props["hsm"] == "true"
        assert props["serial"] == "SER-0001"
        # and the native document is still the authority
        native = await c.get("/api/v1/hbom")
        meta_props = {p["name"]: p["value"] for p in cd["metadata"]["properties"]}
        assert meta_props["cryptoscan:hbom-content-hash"] == native.json()["content_hash"]
    engine.dispose()


@pytest.mark.asyncio
async def test_pin_is_content_addressed_idempotent_and_listed():
    app, session, engine = _make_app()
    _seed_hsm(session)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        pinned = await c.post("/api/v1/hbom/snapshot")
        assert pinned.status_code == 200, pinned.text
        body = pinned.json()
        assert body["created"] is True
        assert body["component_count"] == 1
        assert len(body["content_hash"]) == 64
        assert body["verify_path"] == f"/api/v1/hbom/snapshots/{body['snapshot_id']}"

        # identical estate -> identical rendering -> collapses to one row
        re_pinned = await c.post("/api/v1/hbom/snapshot")
        assert re_pinned.json()["created"] is False
        assert re_pinned.json()["snapshot_id"] == body["snapshot_id"]

        listed = await c.get("/api/v1/hbom/snapshots")
        assert listed.status_code == 200
        assert listed.json()["count"] == 1
        assert listed.json()["snapshots"][0]["content_hash"] == body["content_hash"]

        # an estate change moves the hash, so a NEW pin lands
        _seed_tpm(session)
        after = await c.post("/api/v1/hbom/snapshot")
        assert after.json()["created"] is True
        assert after.json()["content_hash"] != body["content_hash"]
        assert after.json()["component_count"] == 2
        listed2 = await c.get("/api/v1/hbom/snapshots")
        assert listed2.json()["count"] == 2
    engine.dispose()


@pytest.mark.asyncio
async def test_snapshot_served_verbatim_with_integrity_self_check():
    app, session, engine = _make_app()
    _seed_hsm(session)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        pinned = (await c.post("/api/v1/hbom/snapshot")).json()
        sid = pinned["snapshot_id"]

        served = await c.get(f"/api/v1/hbom/snapshots/{sid}")
        assert served.status_code == 200, served.text
        doc = served.json()
        assert doc["integrity"] == "OK"
        assert "matches the pinned content hash" in doc["integrity_note"]
        # verbatim: the stored payload equals what the live route generated
        live = (await c.get("/api/v1/hbom")).json()
        assert doc["payload"] == live
        assert doc["payload"]["content_hash"] == pinned["content_hash"]

        # a post-pin mutation is detected, never served as trusted
        row = session.query(HbomSnapshot).filter(HbomSnapshot.id == sid).one()
        row.payload = dict(row.payload)
        row.payload["components"][0]["manufacturer"] = "NotUtimaco"
        session.commit()
        tampered = await c.get(f"/api/v1/hbom/snapshots/{sid}")
        assert tampered.json()["integrity"] == "MISMATCH"
        assert "Do not trust it" in tampered.json()["integrity_note"]

        unknown = await c.get("/api/v1/hbom/snapshots/does-not-exist")
        assert unknown.status_code == 404
    engine.dispose()
