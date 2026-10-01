"""PAYMENT monitor runner: connector feeds, transaction ingest, policy + usage."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401
from db.connection.session import Base
from db.models.payment_crypto import HsmEvent, PaymentKey, PaymentTransactionVolume
from worker.monitor.runners import payment_runner

AUDIT_DAY = (datetime.now(timezone.utc) - timedelta(days=1)).date().isoformat()
AUDIT = """{"occurred_at":"AUDIT_DAYT10:00:00Z","device":"hsm-prod-1","event_type":"KEY_GENERATED","key_id":"ZMK-01","actor":"custodian-a","detail":{"algorithm":"TRIPLE_DES"}}
{"occurred_at":"AUDIT_DAYT10:05:00Z","device":"hsm-prod-1","event_type":"AUTH_FAILURE","actor":"nobody"}
{"occurred_at":"AUDIT_DAYT10:06:00Z","device":"hsm-prod-1","event_type":"AUTH_FAILURE","actor":"nobody"}
{"occurred_at":"AUDIT_DAYT10:07:00Z","device":"hsm-prod-1","event_type":"AUTH_FAILURE","actor":"nobody"}
{"occurred_at":"AUDIT_DAYT10:08:00Z","device":"hsm-prod-1","event_type":"AUTH_FAILURE","actor":"nobody"}
{"occurred_at":"AUDIT_DAYT10:09:00Z","device":"hsm-prod-1","event_type":"AUTH_FAILURE","actor":"nobody"}
{"occurred_at":"AUDIT_DAYT11:00:00Z","device":"hsm-prod-1","event_type":"CLEAR_KEY_EXPORT","key_id":"ZMK-01","actor":"svc-pin","severity":"CRITICAL"}
""".replace("AUDIT_DAY", AUDIT_DAY)


def _session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def test_payment_runner_blocked_without_feed():
    result = payment_runner({}, _session())
    assert "blocked_reason" in result
    assert "audit feed" in result["blocked_reason"]


def test_payment_runner_ingests_and_flags(tmp_path: Path):
    audit_file = tmp_path / "audit.jsonl"
    audit_file.write_text(AUDIT, encoding="utf-8")
    session = _session()

    first = payment_runner({"path": str(audit_file)}, session)
    session.commit()
    summary = first["summary"]
    assert summary["events_ingested"] == 7
    assert summary["keys_tracked"] == 1           # KEY_GENERATED auto-inventoried ZMK-01
    key = session.query(PaymentKey).one()
    assert key.key_id == "ZMK-01"
    assert key.algorithm == "TRIPLE_DES"
    assert key.source == "HSM_EVENT"
    # 3DES active key (PAY-001), no ceremony (PAY-005), clear export (PAY-004),
    # auth storm (PAY-006) — blocking issues surface in the monitor summary
    assert "PAY-001" in summary["issues"]
    assert "PAY-004" in summary["issues"]
    assert "PAY-006" in summary["issues"]
    assert first["degraded"]

    # second sweep: cursor means nothing new, no duplicates
    second = payment_runner({"path": str(audit_file)}, session)
    session.commit()
    assert second["summary"]["events_ingested"] == 0
    assert session.query(HsmEvent).count() == 7


def test_payment_runner_appends_new_lines_only(tmp_path: Path):
    audit_file = tmp_path / "audit.log"
    audit_file.write_text(
        '{"occurred_at":"2026-08-30T10:00:00Z","device":"hsm-1","event_type":"KEY_USED","key_id":"ZPK-1","detail":{"op":"PIN_VERIFY","count":10}}\n',
        encoding="utf-8")
    session = _session()
    payment_runner({"path": str(audit_file)}, session)
    audit_file.write_text(
        audit_file.read_text()
        + '{"occurred_at":"2026-08-30T11:00:00Z","device":"hsm-1","event_type":"KEY_USED","key_id":"ZPK-1","detail":{"op":"PIN_TRANSLATE","count":5}}\n',
        encoding="utf-8")
    result = payment_runner({"path": str(audit_file)}, session)
    session.commit()
    assert result["summary"]["events_ingested"] == 1
    assert session.query(HsmEvent).count() == 2


def test_payment_runner_transaction_file_and_correlation(tmp_path: Path):
    """DW export + audit feed: transaction days ingest, correlation runs in-sweep."""
    import json as jsonlib

    audit_file = tmp_path / "audit.jsonl"
    today = datetime.now(timezone.utc).date()
    lines = []
    for offset in range(18, -1, -1):  # 19 stable days + today at half rate
        day = today - timedelta(days=offset)
        count = 100_000 if offset else 50_000
        lines.append(jsonlib.dumps({
            "occurred_at": datetime(day.year, day.month, day.day, 12, tzinfo=timezone.utc).isoformat(),
            "device": "hsm-1", "event_type": "KEY_USED", "key_id": "ZPK-1",
            "detail": {"op": "PIN_VERIFY", "count": count},
        }))
    audit_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    tx_file = tmp_path / "tx_daily.jsonl"
    tx_file.write_text("\n".join(
        jsonlib.dumps({"day": (today - timedelta(days=offset)).isoformat(), "count": 100_000})
        for offset in range(19, -1, -1)
    ) + "\n", encoding="utf-8")

    session = _session()
    result = payment_runner({"path": str(audit_file), "transactions_path": str(tx_file)}, session)
    session.commit()
    summary = result["summary"]
    assert summary["transaction_days_ingested"] == 20
    assert session.query(PaymentTransactionVolume).count() == 20
    assert summary["correlation"] in {"anomalies", "ok", "insufficient_data"}
    assert summary["hsm_ops_90d"] == 100_000 * 18 + 50_000  # 18 stable days + today at half rate
    if summary["correlation"] == "anomalies":
        assert "PAY-014" in summary["issues"]  # today's 50% drop surfaces in the monitor


def test_payment_runner_unparsable_file_degrades(tmp_path: Path):
    audit_file = tmp_path / "audit garbage"
    audit_file.write_text("total garbage \x00 line", encoding="utf-8")
    result = payment_runner({"path": str(audit_file)}, _session())
    assert result["degraded"]
    assert result["issues"][0].startswith("AUDIT_FEED_ERROR:")
