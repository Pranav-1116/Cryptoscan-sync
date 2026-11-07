"""Payment usage API: transaction series, usage report, evaluate merge, PCI report."""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401
from api.dependencies import get_current_user, get_db_session, require_auditor
from api.main import create_app
from db.connection.session import Base

NOW = datetime(2026, 8, 30, tzinfo=timezone.utc)


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


def _usage_event(session, days_ago: int, key_id: str = "ZPK-PROD-04", op: str = "PIN_VERIFY"):
    from db.repositories.payment_crypto_repository import PaymentCryptoRepository

    PaymentCryptoRepository(session).add_events([{
        "occurred_at": (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat(),
        "device": "hsm-prod-1", "event_type": "KEY_USED", "key_id": key_id,
        "detail": {"op": op},
    }])


@pytest.mark.asyncio
async def test_transactions_usage_and_evaluate_merge():
    app, session, engine = _make_app()
    from db.repositories.payment_crypto_repository import PaymentCryptoRepository

    repo = PaymentCryptoRepository(session)
    repo.upsert_key({"key_id": "ZPK-PROD-04", "key_usage": "ZONE_PIN_KEY_ZPK",
                     "algorithm": "AES", "state": "ACTIVE",
                     "activation_at": datetime.now(timezone.utc) - timedelta(days=200)})
    session.commit()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        bad_day = await client.post("/api/v1/payment-crypto/transactions",
                                    json={"day": "31-02-2026", "count": 100})
        assert bad_day.status_code == 422

        # 20 days of 10M transactions
        for offset in range(20):
            day = (date.today() - timedelta(days=offset)).isoformat()
            posted = await client.post("/api/v1/payment-crypto/transactions",
                                       json={"day": day, "count": 10_000_000, "source": "core-banking"})
            assert posted.status_code == 200

        # usage events: today (anomaly: far below the 1.08 ops/tx a 10M day needs)
        _usage_event(session, days_ago=0)
        _usage_event(session, days_ago=1, key_id="GHOST-KEY")
        session.commit()

        usage = await client.get("/api/v1/payment-crypto/usage")
        assert usage.status_code == 200
        body = usage.json()
        assert body["total_usage_events"] == 2
        rules = {finding["rule_id"] for finding in body["findings"]}
        assert "PAY-013" in rules                       # GHOST-KEY is a shadow key
        assert body["correlation"]["status"] in {"insufficient_data", "anomalies", "ok"}

        evaluation = await client.post("/api/v1/payment-crypto/evaluate")
        assert evaluation.status_code == 200
        evaluated_rules = {finding["rule_id"] for finding in evaluation.json()["findings"]}
        assert {"PAY-005", "PAY-013"} <= evaluated_rules  # inventory + usage rules merged


@pytest.mark.asyncio
async def test_bulk_transaction_series_upsert():
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # one bad key is per-item REJECTED with a reason — the rest of the
        # batch is never rejected with it (gap analysis §B partial success)
        mixed = await client.post("/api/v1/payment-crypto/transactions/bulk",
                                  json={"series": {"31-02-2026": 5, "2026-08-29": 10_000_000}})
        assert mixed.status_code == 200
        body = mixed.json()
        assert body["partial"] is True
        by_key = {row["key"]: row for row in body["items"]}
        assert by_key["31-02-2026"]["outcome"] == "REJECTED"
        assert "invalid ISO date" in by_key["31-02-2026"]["reason"]
        assert by_key["2026-08-29"]["outcome"] == "ACCEPTED"
        assert body["totals"] == {"accepted": 1, "rejected": 1, "skipped": 0, "total": 2}

        posted = await client.post("/api/v1/payment-crypto/transactions/bulk",
                                   json={"series": {"2026-08-29": 10_000_000, "2026-08-30": 10_500_000},
                                         "source": "dw-push"})
        assert posted.status_code == 200, posted.text
        # 2026-08-29 is written again with the same value -> SKIPPED "unchanged"
        assert posted.json()["days_ingested"] == 1
        # upsert: same day, new count — no duplicate row
        again = await client.post("/api/v1/payment-crypto/transactions/bulk",
                                  json={"series": {"2026-08-30": 9_900_000}})
        assert again.status_code == 200
        assert again.json()["items"] == [
            {"key": "2026-08-30", "outcome": "ACCEPTED", "reason": "written"}]
        from db.models.payment_crypto import PaymentTransactionVolume

        rows = session.query(PaymentTransactionVolume).order_by(PaymentTransactionVolume.day).all()
        assert [(row.day.isoformat(), row.transaction_count) for row in rows] == [
            ("2026-08-29", 10_000_000), ("2026-08-30", 9_900_000)]

        # unchanged value is SKIPPED with its own reason, not fake-accepted
        unchanged = await client.post("/api/v1/payment-crypto/transactions/bulk",
                                      json={"series": {"2026-08-30": 9_900_000}})
        assert unchanged.json()["items"] == [
            {"key": "2026-08-30", "outcome": "SKIPPED", "reason": "value unchanged"}]


@pytest.mark.asyncio
async def test_bulk_write_is_idempotent_with_idempotency_key():
    app, session, engine = _make_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {"series": {"2026-09-01": 1_000}}
        first = await client.post("/api/v1/payment-crypto/transactions/bulk",
                                  json=payload, headers={"Idempotency-Key": "dw-2026-09-01"})
        assert first.status_code == 200
        assert first.json()["idempotent_replay"] is False
        assert first.json()["totals"]["accepted"] == 1

        replay = await client.post("/api/v1/payment-crypto/transactions/bulk",
                                   json=payload, headers={"Idempotency-Key": "dw-2026-09-01"})
        assert replay.status_code == 200
        body = replay.json()
        assert body["idempotent_replay"] is True
        assert body["totals"] == {"accepted": 0, "rejected": 0, "skipped": 1, "total": 1}
        assert body["items"][0]["reason"] == "idempotent replay of dw-2026-09-01"

        from db.models.payment_crypto import PaymentTransactionVolume
        rows = session.query(PaymentTransactionVolume).all()
        assert len(rows) == 1, "the replay must not write again"

        # the same key with a different body is a CONFLICT, never a wrong answer
        conflict = await client.post("/api/v1/payment-crypto/transactions/bulk",
                                     json={"series": {"2026-09-01": 9_999}},
                                     headers={"Idempotency-Key": "dw-2026-09-01"})
        assert conflict.status_code == 409
        assert conflict.json()["error_code"] == "CONFLICT"
        assert conflict.json()["request_id"]


@pytest.mark.asyncio
async def test_forecast_endpoint_includes_keys_and_certificates():
    from datetime import timedelta

    app, session, engine = _make_app()
    from db.repositories.payment_crypto_repository import PaymentCryptoRepository

    repo = PaymentCryptoRepository(session)
    repo.upsert_key({"key_id": "ZMK-SOON", "algorithm": "AES", "state": "ACTIVE",
                     "expiry_at": datetime.now(timezone.utc) + timedelta(days=14)})
    session.commit()

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        forecast = await client.get("/api/v1/payment-crypto/forecast")
        assert forecast.status_code == 200, forecast.text
        body = forecast.json()
        assert body["upcoming_count"] >= 1
        assert any(item["reference"] == "ZMK-SOON" for item in body["upcoming"])
        pay015 = [f for f in body["findings"] if f["rule_id"] == "PAY-015"]
        assert pay015 and pay015[0]["key_id"] == "ZMK-SOON"  # no ceremony scheduled
        assert "rotation_calendar" in body


@pytest.mark.asyncio
async def test_payment_findings_flow_into_pci_report():
    """PAY-xxx findings must evaluate the new PCI requirements (integration)."""
    from reporting.compliance_report import render_json

    payment = {
        "summary": {"keys_total": 3, "active_weak_algorithm_keys": 1, "ceremonies_total": 1},
        "findings": [
            {"rule_id": "PAY-003", "key_id": "ZMK-1", "severity": 5, "blocking": True, "message": "no dual control"},
            {"rule_id": "PAY-002", "key_id": "ZMK-2", "severity": 4, "blocking": False, "message": "stale"},
        ],
    }
    report = render_json(scan={"scan_id": "s1"}, findings=[], template_id="pci-dss-4.0", payment=payment)
    by_id = {row["id"]: row for row in report["template_evaluation"]["requirements"]}
    assert by_id["3.6.5-pay"]["status"] == "FAIL"        # PAY-003 evidence
    assert "PAY-003" in by_id["3.6.5-pay"]["rules"]
    assert by_id["3.7-pay-rotation"]["status"] == "FAIL"  # PAY-002 evidence
    assert by_id["3.6-pay-usable"]["status"] == "NOT_EVALUATED"  # honest: no PAY-009/012 evidence
    assert report["payment_crypto"]["open_findings"] == 2
    assert report["payment_crypto"]["keys_total"] == 3
    # hash still reproducible (payment block covered by canonical hash)
    from reporting.report_templates import canonical_hash

    assert report["report_hash"] == canonical_hash(
        {key: value for key, value in report.items() if key != "report_hash"}
    )
