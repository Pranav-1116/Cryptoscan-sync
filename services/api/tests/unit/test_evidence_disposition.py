"""Evidence disposition surface (§4.2 P0, round 40).

Historical rows committed before snippet sanitization may still hold raw
detector text at rest. The inventory must find them WITHOUT returning the
content; decisions are audited and append-only; QUARANTINE_EXPORTS /
MARK_REDACTED refuse scan exports; RETAIN changes nothing; and no path
rewrites finding_data or hashes.
"""

from __future__ import annotations

import json
import os

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401
from api.dependencies import get_current_user, get_db_session, require_admin, require_auditor
from api.main import create_app
from db.connection.session import Base
from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan

SECRET_SNIPPET = "sk-live-SUPERSECRETDO_NOT_LEAK"


def _make_app(current_user: str = "admin-1"):
    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: current_user
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    app.dependency_overrides[require_admin] = lambda: current_user
    app.dependency_overrides[require_auditor] = lambda: current_user
    return app, session, engine


def _seed_scan(session, scan_id: str) -> None:
    from datetime import datetime, timezone

    session.add(Scan(id=scan_id, status="COMPLETED", target_location="local://x",
                     target_type="LOCAL_DIRECTORY", operator="t",
                     scan_start=datetime.now(timezone.utc)))


def _seed_row(session, scan_id: str, evidence_id: str, finding_data: dict) -> None:
    session.add(EvidenceRecord(
        id=evidence_id, scan_id=scan_id, content_hash="h" * 64, chain_hash="c" * 64,
        chain_position=0, algorithm="RSA", file_path="src/x.py", line_number=1,
        finding_data=finding_data,
    ))


DIRTY_FINDING = {
    "crypto": {"algorithm": "RSA", "key_size": 2048},
    "source": {"file_path": "src/x.py", "line_number": 3, "code_snippet": SECRET_SNIPPET},
    "metadata": {"confidence": "HIGH"},
}
CLEAN_FINDING = {
    "crypto": {"algorithm": "RSA", "key_size": 2048},
    "source": {"file_path": "src/x.py", "line_number": 3},
    "metadata": {"confidence": "HIGH"},
}


@pytest.mark.asyncio
async def test_inventory_finds_dirty_rows_without_leaking_content():
    app, session, engine = _make_app()
    _seed_scan(session, "scan-dirty")
    _seed_scan(session, "scan-clean")
    _seed_row(session, "scan-dirty", "ev-d1", DIRTY_FINDING)
    _seed_row(session, "scan-dirty", "ev-d2", CLEAN_FINDING)
    _seed_row(session, "scan-clean", "ev-c1", CLEAN_FINDING)
    session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
        r = await ac.get("/api/v1/evidence/disposition/inventory")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["affected_scan_count"] == 1
    entry = body["affected_scans"][0]
    assert entry["scan_id"] == "scan-dirty"
    assert entry["affected_records"] == 1
    assert entry["records_inspected"] == 2
    assert "source.code_snippet" in entry["triggering_fields"]
    assert entry["disposition"] == "NONE"
    # the sensitive content itself never leaves the database
    assert SECRET_SNIPPET not in json.dumps(body)
    assert any("never returns the sensitive content" in n for n in body["notes"])
    engine.dispose()


@pytest.mark.asyncio
async def test_decision_is_recorded_audited_and_append_only():
    app, session, engine = _make_app()
    _seed_scan(session, "scan-a")
    session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
        r = await ac.post("/api/v1/evidence/disposition", json={
            "scan_id": "scan-a", "decision": "RETAIN", "notes": "reviewed; keep",
            "affected_records": 3,
        })
        assert r.status_code == 200, r.text
        first = r.json()
        assert first["decision"] == "RETAIN"
        assert first["decided_by"] == "admin-1"

        r2 = await ac.post("/api/v1/evidence/disposition", json={
            "scan_id": "scan-a", "decision": "QUARANTINE_EXPORTS",
            "notes": "escalated; quarantine pending reissue",
        })
        assert r2.status_code == 200, r2.text

        trail = await ac.get("/api/v1/evidence/disposition/scan-a")
    assert [d["decision"] for d in trail.json()] == ["RETAIN", "QUARANTINE_EXPORTS"]

    # the audit ledger carries the decision
    from db.models.user import AuditLog
    rows = session.query(AuditLog).order_by(AuditLog.created_at).all()
    assert any(a.action == "evidence.disposition" and a.target_id == "scan-a" for a in rows)
    engine.dispose()


@pytest.mark.asyncio
async def test_invalid_decision_and_unknown_scan_are_refused():
    app, session, engine = _make_app()
    _seed_scan(session, "scan-a")
    session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
        r = await ac.post("/api/v1/evidence/disposition", json={
            "scan_id": "scan-a", "decision": "DELETE_EVERYTHING", "notes": "no"})
        assert r.status_code == 422
        r = await ac.post("/api/v1/evidence/disposition", json={
            "scan_id": "scan-missing", "decision": "RETAIN", "notes": "x"})
        assert r.status_code == 404
    engine.dispose()


@pytest.mark.asyncio
async def test_quarantine_refuses_exports_and_retain_does_not():
    app, session, engine = _make_app()
    _seed_scan(session, "scan-q")
    _seed_row(session, "scan-q", "ev-q1", CLEAN_FINDING)
    session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
        # before any decision the export works
        ok = await ac.get("/api/v1/scans/scan-q/export")
        assert ok.status_code == 200, ok.text

        r = await ac.post("/api/v1/evidence/disposition", json={
            "scan_id": "scan-q", "decision": "QUARANTINE_EXPORTS", "notes": "pending reissue"})
        assert r.status_code == 200

        refused = await ac.get("/api/v1/scans/scan-q/export")
        assert refused.status_code == 409
        assert "quarantined by an operator disposition" in refused.json()["detail"]

        refused_csv = await ac.get("/api/v1/scans/scan-q/export.csv")
        assert refused_csv.status_code == 409

        # superseding decision lifts the quarantine
        r2 = await ac.post("/api/v1/evidence/disposition", json={
            "scan_id": "scan-q", "decision": "RETAIN", "notes": "reissued chain verified"})
        assert r2.status_code == 200
        ok2 = await ac.get("/api/v1/scans/scan-q/export")
        assert ok2.status_code == 200
    engine.dispose()


@pytest.mark.asyncio
async def test_mark_redacted_also_refuses_exports():
    app, session, engine = _make_app()
    _seed_scan(session, "scan-r")
    _seed_row(session, "scan-r", "ev-r1", DIRTY_FINDING)
    session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
        r = await ac.post("/api/v1/evidence/disposition", json={
            "scan_id": "scan-r", "decision": "MARK_REDACTED", "notes": "of-record redaction"})
        assert r.status_code == 200
        refused = await ac.get("/api/v1/scans/scan-r/export")
        assert refused.status_code == 409
        assert "MARK_REDACTED" in refused.json()["detail"]
    engine.dispose()


@pytest.mark.asyncio
async def test_disposition_never_rewrites_stored_evidence():
    app, session, engine = _make_app()
    _seed_scan(session, "scan-w")
    _seed_row(session, "scan-w", "ev-w1", DIRTY_FINDING)
    session.commit()
    before = dict(session.get(EvidenceRecord, "ev-w1").finding_data)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
        r = await ac.post("/api/v1/evidence/disposition", json={
            "scan_id": "scan-w", "decision": "MARK_REDACTED", "notes": "x"})
        assert r.status_code == 200

    session.expire_all()
    row = session.get(EvidenceRecord, "ev-w1")
    assert row.finding_data == before  # chain commitment untouched
    assert row.content_hash == "h" * 64
    engine.dispose()
