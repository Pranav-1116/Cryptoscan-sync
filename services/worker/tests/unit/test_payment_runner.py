"""PAYMENT monitor runner: audit-trail tailing, dedupe, auto-inventory, policy."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401
from db.connection.session import Base
from db.models.payment_crypto import HsmEvent, PaymentKey
from worker.monitor.runners import payment_runner

AUDIT = """{"occurred_at":"2026-08-30T10:00:00Z","device":"hsm-prod-1","event_type":"KEY_GENERATED","key_id":"ZMK-01","actor":"custodian-a","detail":{"algorithm":"TRIPLE_DES"}}
{"occurred_at":"2026-08-30T10:05:00Z","device":"hsm-prod-1","event_type":"AUTH_FAILURE","actor":"nobody"}
{"occurred_at":"2026-08-30T10:06:00Z","device":"hsm-prod-1","event_type":"AUTH_FAILURE","actor":"nobody"}
{"occurred_at":"2026-08-30T10:07:00Z","device":"hsm-prod-1","event_type":"AUTH_FAILURE","actor":"nobody"}
{"occurred_at":"2026-08-30T10:08:00Z","device":"hsm-prod-1","event_type":"AUTH_FAILURE","actor":"nobody"}
{"occurred_at":"2026-08-30T10:09:00Z","device":"hsm-prod-1","event_type":"AUTH_FAILURE","actor":"nobody"}
{"occurred_at":"2026-08-30T11:00:00Z","device":"hsm-prod-1","event_type":"CLEAR_KEY_EXPORT","key_id":"ZMK-01","actor":"svc-pin","severity":"CRITICAL"}
"""


def _session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def test_payment_runner_blocked_without_path():
    result = payment_runner({}, _session())
    assert "blocked_reason" in result
    assert "path" in result["blocked_reason"]


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

    # second sweep: nothing new -> zero ingested, same findings, no duplicates
    second = payment_runner({"path": str(audit_file)}, session)
    session.commit()
    assert second["summary"]["events_ingested"] == 0
    assert session.query(HsmEvent).count() == 7


def test_payment_runner_unparsable_file_degrades(tmp_path: Path):
    audit_file = tmp_path / "audit garbage"
    audit_file.write_text("total garbage \x00 line", encoding="utf-8")
    result = payment_runner({"path": str(audit_file)}, _session())
    assert result["degraded"]
    assert result["issues"][0].startswith("UNPARSABLE_AUDIT_LOG:")
