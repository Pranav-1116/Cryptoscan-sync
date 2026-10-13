"""Requirements register over the API (§4.3, round 47).

requirement → exact evidence / gaps / expiry / reviewer sign-off, backed by
PERSISTED, content-addressed evidence packs and durable attestations. A pack
that was never pinned (or fails its integrity self-check) leaves every
requirement honestly unevaluated — the interface never turns missing data
into a green score.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register tables
from api.dependencies import get_current_user, get_db_session
from api.main import create_app
from db.connection.session import Base
from db.models.compliance_record import ComplianceAttestation, ComplianceEvidencePack

NOW = datetime(2026, 10, 13, tzinfo=timezone.utc)


def _make_app(user: str = "admin"):
    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "compliance-req-" + "q" * 21)
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    return app, session, engine


def _pack_payload(statuses: dict[str, str], *, age_days: float = 0.0) -> dict:
    controls = [{"control": k, "status": v, "checked_at": NOW.isoformat(), "evidence": {}} for k, v in statuses.items()]
    return {
        "generated_at": (NOW - timedelta(days=age_days)).isoformat(),
        "controls": controls,
        "summary": {"pass": len(statuses), "fail": 0, "unknown": 0},
    }


def _sha(payload: dict) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()


def _seed_pack(session, statuses: dict[str, str], *, age_days: float = 0.0) -> dict:
    payload = _pack_payload(statuses, age_days=age_days)
    row = ComplianceEvidencePack(
        pack_sha256=_sha(payload),
        payload=payload,
        summary=payload["summary"],
        generated_at=NOW - timedelta(days=age_days),
        collected_by="admin",
    )
    session.add(row)
    session.commit()
    session.refresh(row)
    return {"pack_id": row.id, "pack_sha256": row.pack_sha256, "payload": payload}


ALL_PASS = {
    "access.session_config": "pass",
    "config.production_gate": "pass",
    "protection.rate_limits": "pass",
    "audit.chain_integrity": "pass",
    "deploy.schema_in_sync": "pass",
    "retention.worm_policy": "pass",
}


@pytest.mark.asyncio
async def test_no_pinned_pack_reports_no_evidence_never_a_score():
    app, session, engine = _make_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        res = await c.get("/api/v1/compliance/requirements")
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["pack"] is None
        assert "not evaluated" in body["note"]
        assert all(r["standing"] == "no_evidence" for r in body["requirements"])
        assert body["summary"]["closed"] == 0
        assert body["summary"]["denominator"] == len(body["requirements"])
    engine.dispose()


@pytest.mark.asyncio
async def test_register_maps_evidence_gap_expiry_and_sign_off():
    app, session, engine = _make_app()
    seeded = _seed_pack(session, ALL_PASS, age_days=100)  # 90d windows expire
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        # reviewer signs the 365-day retention requirement over the pinned pack
        signed = await c.post(
            "/api/v1/compliance/attestations",
            json={"scope": "RETENTION-WORM", "signed_by": "ciso@example.com", "pack_sha256": seeded["pack_sha256"]},
        )
        assert signed.status_code == 200, signed.text
        assert signed.json()["persisted"] is True
        assert len(signed.json()["jws"].split(".")) == 3

        res = await c.get("/api/v1/compliance/requirements")
        assert res.status_code == 200
        body = res.json()
        rows = {r["requirement"]: r for r in body["requirements"]}

        # 90-day window: 100-day-old evidence is EXPIRED, not quietly green
        assert rows["SOC2-CC6.1"]["standing"] == "expired"
        assert rows["SOC2-CC6.1"]["expiry"]["state"] == "expired"
        assert rows["SOC2-CC6.1"]["gap"]  # the gap statement travels with the row

        # 365-day window + fresh signature: evidenced and closed
        retention = rows["RETENTION-WORM"]
        assert retention["standing"] == "evidenced"
        assert retention["closed"] is True
        assert retention["sign_off"]["state"] == "signed"
        assert retention["sign_off"]["records"][0]["signed_by"] == "ciso@example.com"
        assert retention["sign_off"]["records"][0]["jws_valid"] is True

        # pass + fresh but unsigned: awaiting sign-off, not closed — the
        # 30-day audit requirement is also expired at 100 days; every window
        # honestly refuses to read stale evidence as current
        assert rows["SOC2-CC7.2"]["standing"] == "expired"
        assert rows["SOC2-CC7.2"]["closed"] is False

        # unmapped requirements stay visible and unevaluated
        assert rows["PCI-DSS-4.2.1"]["standing"] == "unevaluated"
        assert rows["PCI-DSS-4.2.1"]["mapped_controls"] == []
        assert rows["PCI-DSS-4.2.1"]["gap"]

        # summary keeps the explicit full-register denominator
        assert body["summary"]["denominator"] == len(body["requirements"])
        assert body["summary"]["closed"] == 1
    engine.dispose()


@pytest.mark.asyncio
async def test_fresh_passing_pack_without_signatures_awaits_sign_off():
    app, session, engine = _make_app()
    _seed_pack(session, ALL_PASS, age_days=0)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        res = await c.get("/api/v1/compliance/requirements")
        rows = {r["requirement"]: r for r in res.json()["requirements"]}
        for req_id in ("SOC2-CC6.1", "SOC2-CC7.2", "RETENTION-WORM"):
            assert rows[req_id]["standing"] == "awaiting_sign_off", req_id
            assert rows[req_id]["closed"] is False
        assert res.json()["summary"]["closed"] == 0
        assert res.json()["summary"]["signed"] == 0
    engine.dispose()


@pytest.mark.asyncio
async def test_pinned_pack_served_verbatim_with_integrity_self_check():
    app, session, engine = _make_app()
    seeded = _seed_pack(session, ALL_PASS)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        res = await c.get(f"/api/v1/compliance/evidence/packs/{seeded['pack_id']}")
        assert res.status_code == 200
        body = res.json()
        assert body["integrity"] == "OK"
        assert body["payload"] == seeded["payload"]  # verbatim, not regenerated
        assert body["pack_sha256"] == seeded["pack_sha256"]

        # tamper with the stored payload → detected, never served as trusted
        row = session.get(ComplianceEvidencePack, seeded["pack_id"])
        row.payload = {
            **row.payload,
            "controls": [{"control": "access.session_config", "status": "pass", "evidence": {"forged": True}}],
        }
        session.commit()
        res = await c.get(f"/api/v1/compliance/evidence/packs/{seeded['pack_id']}")
        assert res.json()["integrity"] == "MISMATCH"
        assert "not trusted" in res.json()["note"]

        # the requirements evaluation fails closed on a tampered latest pack
        res = await c.get("/api/v1/compliance/requirements")
        body = res.json()
        assert body["pack"]["integrity"] == "MISMATCH"
        assert all(r["standing"] == "no_evidence" for r in body["requirements"])
        assert body["summary"]["closed"] == 0
    engine.dispose()


@pytest.mark.asyncio
async def test_signing_an_unpinned_pack_is_refused():
    app, session, engine = _make_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        res = await c.post(
            "/api/v1/compliance/attestations",
            json={"scope": "SOC2-CC6.1", "signed_by": "ciso@example.com", "pack_sha256": "f" * 64},
        )
        assert res.status_code == 404
        assert "no persisted evidence pack" in res.json()["detail"]
    engine.dispose()


@pytest.mark.asyncio
async def test_tampered_attestation_signature_counts_as_invalid_not_signed():
    app, session, engine = _make_app()
    seeded = _seed_pack(session, ALL_PASS)
    session.add(
        ComplianceAttestation(
            pack_id=seeded["pack_id"],
            pack_sha256=seeded["pack_sha256"],
            scope="SOC2-CC6.1",
            signed_by="someone@example.com",
            jws="not-a-jws.at-all",  # forged/garbage signature
            snapshot={},
            signed_at=NOW,
        )
    )
    session.commit()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        res = await c.get("/api/v1/compliance/requirements")
        rows = {r["requirement"]: r for r in res.json()["requirements"]}
        cc61 = rows["SOC2-CC6.1"]
        assert cc61["sign_off"]["state"] == "invalid"
        assert cc61["standing"] == "awaiting_sign_off"  # invalid ≠ signed

        listing = await c.get("/api/v1/compliance/attestations")
        record = listing.json()["attestations"][0]
        assert record["jws_valid"] is False
        assert "rotated or tampered" in record["note"]
    engine.dispose()


@pytest.mark.asyncio
async def test_snapshot_endpoint_pins_the_live_pack():
    app, session, engine = _make_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        res = await c.post("/api/v1/compliance/evidence/packs")
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["created"] is True
        assert len(body["pack_sha256"]) == 64
        assert body["controls"] >= 1

        served = await c.get(body["verify_path"])
        assert served.status_code == 200
        assert served.json()["integrity"] == "OK"

        # requirements now evaluate against the pinned pack
        reqs = await c.get("/api/v1/compliance/requirements")
        assert reqs.json()["pack"]["pack_id"] == body["pack_id"]
        standings = {r["standing"] for r in reqs.json()["requirements"]}
        assert "no_evidence" not in standings
    engine.dispose()


@pytest.mark.asyncio
async def test_non_admin_cannot_pin_or_sign():
    app, session, engine = _make_app(user="auditor")
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        assert (await c.post("/api/v1/compliance/evidence/packs")).status_code == 403
        assert (
            await c.post(
                "/api/v1/compliance/attestations",
                json={"scope": "SOC2-CC6.1", "signed_by": "x", "pack_sha256": "0" * 64},
            )
        ).status_code == 403
        assert (await c.get("/api/v1/compliance/requirements")).status_code == 403
    engine.dispose()
