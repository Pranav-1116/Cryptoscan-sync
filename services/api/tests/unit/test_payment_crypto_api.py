"""Payment crypto API: keys, ceremonies, HSM ingest, evaluate, findings."""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401
from api.dependencies import get_current_user, get_db_session, require_auditor
from api.main import create_app
from db.connection.session import Base


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
    app.dependency_overrides[get_current_user] = lambda: "soc"
    app.dependency_overrides[require_auditor] = lambda: "soc-auditor"
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    return app, session, engine


@pytest.mark.asyncio
async def test_key_lifecycle_with_tr31_and_summary():
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        created = await client.post("/api/v1/payment-crypto/keys", json={
            "key_id": "ZMK-01", "hsm_device": "hsm-prod-1", "key_usage": "ZONE_MASTER_KEY_ZMK",
            "algorithm": "TRIPLE_DES", "state": "ACTIVE",
            "activation_at": "2024-01-01T00:00:00Z",
            "key_block": "B00401B001N0" + "0000" + "00" * 16,
        })
        assert created.status_code == 200, created.text
        key = created.json()
        assert key["key_block_version"] == "B0"  # parsed from the block
        assert key["key_usage"] == "ZONE_MASTER_KEY_ZMK"

        bad_state = await client.post("/api/v1/payment-crypto/keys", json={
            "key_id": "X", "state": "ON_FIRE"})
        assert bad_state.status_code == 422

        ceremony = await client.post("/api/v1/payment-crypto/ceremonies", json={
            "ceremony_id": "CER-1", "key_id": "ZMK-01", "held_at": "2026-08-01T09:00:00Z",
            "custodians": ["only-custodian"], "dual_control": False})
        assert ceremony.status_code == 200

        events = await client.post("/api/v1/payment-crypto/hsm-events", json={
            "format": "syslog",
            "text": "\n".join(
                f'<30>2026-08-{day:02d}T09:00:00Z hsm-prod-1 crypto: event=auth_fail user=x'
                for day in range(20, 26)
            ) + "\n<30>2026-08-29T10:00:00Z hsm-prod-1 crypto: event=clear_export key_id=ZMK-01 user=svc",
        })
        assert events.status_code == 200, events.text
        assert events.json()["by_type"]["AUTH_FAILURE"] == 6

        evaluation = await client.post("/api/v1/payment-crypto/evaluate")
        assert evaluation.status_code == 200, evaluation.text
        rules = {finding["rule_id"] for finding in evaluation.json()["findings"]}
        assert {"PAY-001", "PAY-002", "PAY-003", "PAY-004", "PAY-006", "PAY-008"} <= rules
        assert evaluation.json()["counts"]["blocking"] >= 2

        summary = await client.get("/api/v1/payment-crypto/summary")
        assert summary.json()["active_weak_algorithm_keys"] == 1
        assert summary.json()["open_findings"] >= 6

        # risk acceptance survives re-evaluation
        blocking = next(f for f in evaluation.json()["findings"] if f["blocking"])
        accept = await client.post(f"/api/v1/payment-crypto/findings/{blocking['id']}/status",
                                   json={"status": "ACCEPTED"})
        assert accept.status_code == 200
        await client.post("/api/v1/payment-crypto/evaluate")
        after = await client.get("/api/v1/payment-crypto/findings")
        accepted = [f for f in after.json()["findings"] if f["status"] == "ACCEPTED"]
        assert len(accepted) == 1  # not silently re-opened


@pytest.mark.asyncio
async def test_ingest_rejects_garbage_and_bad_format():
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        empty = await client.post("/api/v1/payment-crypto/hsm-events",
                                  json={"format": "jsonl", "text": "  "})
        assert empty.status_code == 422
        bad_format = await client.post("/api/v1/payment-crypto/hsm-events",
                                       json={"format": "xml", "text": "<a/>"})
        assert bad_format.status_code == 422
        csv_no_map = await client.post("/api/v1/payment-crypto/hsm-events",
                                       json={"format": "csv", "text": "a,b,c"})
        assert csv_no_map.status_code == 422
        garbage = await client.post("/api/v1/payment-crypto/hsm-events",
                                    json={"format": "jsonl", "text": "{oops"})
        assert garbage.status_code == 200
        assert garbage.json()["accepted"] == 0
        assert garbage.json()["rejected"] == 1
