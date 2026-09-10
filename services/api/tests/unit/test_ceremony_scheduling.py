"""Ceremony scheduling: PLANNED/HELD lifecycle, PAY-015 clearing, PAY-016 overdue."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401
from api.dependencies import get_current_user, get_db_session, require_auditor
from api.main import create_app
from db.connection.session import Base
from payment_crypto.forecast import ExpiryForecaster
from payment_crypto.policy import PaymentPolicyEngine

NOW = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)


def test_planned_ceremony_clears_pay015_and_abandoned_does_not():
    key = {"key_id": "ZMK-1", "expiry_at": (NOW + timedelta(days=30)).isoformat()}
    scheduled = [{"key_id": "ZMK-1", "held_at": (NOW + timedelta(days=10)).isoformat(),
                  "status": "PLANNED"}]
    assert ExpiryForecaster(now=NOW).forecast([key], ceremonies=scheduled)["findings"] == []

    abandoned = [{**scheduled[0], "status": "ABANDONED"}]
    findings = ExpiryForecaster(now=NOW).forecast([key], ceremonies=abandoned)["findings"]
    assert [f["rule_id"] for f in findings] == ["PAY-015"]


def test_pay016_overdue_planned_ceremony():
    overdue = [{"key_id": "ZMK-1", "held_at": "2026-08-01T09:00:00Z", "status": "PLANNED",
                "custodians": ["a", "b"], "dual_control": True, "ceremony_id": "CER-OLD"}]
    findings = PaymentPolicyEngine(now=NOW).evaluate(
        [{"key_id": "ZMK-1", "algorithm": "AES", "state": "ACTIVE",
          "activation_at": (NOW - timedelta(days=5)).isoformat()}],
        ceremonies=overdue,
    )
    rules = {f.rule_id for f in findings}
    assert "PAY-016" in rules
    assert "PAY-003" not in rules  # custodians + dual control are fine here

    held = [{**overdue[0], "status": "HELD"}]
    rules = {f.rule_id for f in PaymentPolicyEngine(now=NOW).evaluate(
        [{"key_id": "ZMK-1", "algorithm": "AES", "state": "ACTIVE",
          "activation_at": (NOW - timedelta(days=5)).isoformat()}], ceremonies=held)}
    assert "PAY-016" not in rules  # it happened


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
async def test_ceremony_lifecycle_via_api():
    from datetime import timezone as tz

    from db.repositories.payment_crypto_repository import PaymentCryptoRepository

    app, session, engine = _make_app()
    repo = PaymentCryptoRepository(session)
    soon = datetime.now(tz.utc) + timedelta(days=30)
    repo.upsert_key({"key_id": "ZMK-LIFE", "algorithm": "AES", "state": "ACTIVE",
                     "expiry_at": soon})
    session.commit()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. future-dated ceremony -> stored as PLANNED
        booked = await client.post("/api/v1/payment-crypto/ceremonies", json={
            "ceremony_id": "CER-LIFE-1", "key_id": "ZMK-LIFE",
            "held_at": (datetime.now(tz.utc) + timedelta(days=7)).isoformat(),
            "custodians": ["a", "b", "c"], "m_of_n": "2-of-3"})
        assert booked.status_code == 200, booked.text
        assert booked.json()["status"] == "PLANNED"

        # 2. PAY-015 cleared for that key
        forecast = await client.get("/api/v1/payment-crypto/forecast")
        pay015 = [f for f in forecast.json()["findings"] if f["key_id"] == "ZMK-LIFE"]
        assert pay015 == []

        # 3. upcoming listing shows the booking
        upcoming = await client.get("/api/v1/payment-crypto/ceremonies?upcoming=true")
        assert [c["ceremony_id"] for c in upcoming.json()["ceremonies"]] == ["CER-LIFE-1"]

        # 4. the ceremony happened -> mark HELD
        marked = await client.patch("/api/v1/payment-crypto/ceremonies/CER-LIFE-1",
                                   json={"status": "HELD"})
        assert marked.status_code == 200
        assert marked.json()["status"] == "HELD"

        # 5. validation + 404 honesty
        bad = await client.patch("/api/v1/payment-crypto/ceremonies/CER-LIFE-1",
                                 json={"status": "MAYBE"})
        assert bad.status_code == 422
        missing = await client.patch("/api/v1/payment-crypto/ceremonies/NOPE",
                                     json={"status": "HELD"})
        assert missing.status_code == 404

        # 6. overdue planned ceremony -> PAY-016 fires in evaluate
        await client.post("/api/v1/payment-crypto/ceremonies", json={
            "ceremony_id": "CER-LATE", "key_id": "ZMK-LIFE",
            "held_at": (datetime.now(tz.utc) - timedelta(days=2)).isoformat(),
            "custodians": ["a", "b"], "dual_control": True})
        _late = session.execute(  # force PLANNED on a past date (missed ceremony)
            __import__("sqlalchemy").text(
                "UPDATE key_ceremonies SET status='PLANNED' WHERE ceremony_id='CER-LATE'"
            )
        )
        session.commit()
        evaluation = await client.post("/api/v1/payment-crypto/evaluate")
        rules = {f["rule_id"] for f in evaluation.json()["findings"]}
        assert "PAY-016" in rules
