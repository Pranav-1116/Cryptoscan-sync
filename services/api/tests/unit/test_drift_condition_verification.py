"""Drift condition-verification API (§4.7, round 40).

POST /drift/evaluate-verification computes evidence-backed verdicts for
administratively RESOLVED events from a later scan's evidence. Only
VERIFIED / CONDITION_PRESENT are stamped; UNCOVERED never becomes a
pass; the audit ledger records every evaluation.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401
from api.dependencies import get_current_user, get_db_session, get_drift_repository, require_auditor
from api.main import create_app
from db.connection.session import Base
from db.models.drift_event import DriftEvent
from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan
from db.repositories.drift_repository import DriftRepository

NOW = datetime.now(timezone.utc)


def _make_app():
    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "test-secret-key-for-sessions-min-32-chars")
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "auditor-1"
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    app.dependency_overrides[require_auditor] = lambda: "auditor-1"
    app.dependency_overrides[get_drift_repository] = lambda: DriftRepository(session)
    return app, session, engine


def _scan(session, scan_id: str, when=NOW, target="local://repo") -> None:
    session.add(Scan(id=scan_id, status="COMPLETED", target_location=target,
                     target_type="LOCAL_DIRECTORY", operator="t", scan_start=when,
                     scan_end=when + timedelta(minutes=5)))


def _evidence(session, scan_id: str, eid: str, algorithm: str, path: str, key_size=None) -> None:
    session.add(EvidenceRecord(
        id=eid, scan_id=scan_id, content_hash="h" * 64, chain_hash="c" * 64,
        chain_position=0, algorithm=algorithm, key_size=key_size,
        file_path=path, line_number=1, finding_data={},
    ))


def _resolved_event(session, event_id: str, scan_id: str, algorithm="RSA",
                    path="src/k.py", key_size=1024, resolved_days_ago=1) -> None:
    session.add(DriftEvent(
        id=event_id, current_scan_id=scan_id, detected_at=NOW - timedelta(days=3),
        drift_type="CHANGED", severity="HIGH",
        drift_details={"current_finding": {
            "algorithm": algorithm, "file_path": path, "key_size": key_size}},
        resolution_status="RESOLVED",
        resolved_by="admin", resolved_at=NOW - timedelta(days=resolved_days_ago),
        resolution_notes="administrative closure",
    ))


@pytest.mark.asyncio
async def test_verified_when_rescan_observes_file_without_condition():
    app, session, engine = _make_app()
    _scan(session, "scan-old")
    _scan(session, "scan-new", when=NOW + timedelta(hours=1))
    _evidence(session, "scan-old", "ev-old", "RSA", "src/k.py", 1024)
    _evidence(session, "scan-new", "ev-new", "RSA", "src/k.py", 4096)  # fixed
    _resolved_event(session, "evt-1", "scan-old")
    session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
        r = await ac.post("/api/v1/drift/evaluate-verification",
                          json={"scan_id": "scan-new"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["counts"] == {"VERIFIED": 1}
    assert body["verdicts"][0]["drift_id"] == "evt-1"

    session.expire_all()
    row = session.get(DriftEvent, "evt-1")
    assert row.verification_status == "VERIFIED"
    assert row.verified_by_scan_id == "scan-new"
    assert row.resolution_status == "RESOLVED"  # administrative state untouched

    from db.models.user import AuditLog
    assert any(a.action == "drift.evaluate_verification" and a.target_id == "scan-new"
               for a in session.query(AuditLog).all())
    engine.dispose()


@pytest.mark.asyncio
async def test_condition_present_when_closure_closed_nothing():
    app, session, engine = _make_app()
    _scan(session, "scan-old")
    _scan(session, "scan-new", when=NOW + timedelta(hours=1))
    _evidence(session, "scan-new", "ev-new", "RSA", "src/k.py", 1024)  # still there
    _resolved_event(session, "evt-2", "scan-old")
    session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
        r = await ac.post("/api/v1/drift/evaluate-verification",
                          json={"scan_id": "scan-new"})
    assert r.status_code == 200
    assert r.json()["counts"] == {"CONDITION_PRESENT": 1}
    session.expire_all()
    assert session.get(DriftEvent, "evt-2").verification_status == "CONDITION_PRESENT"
    engine.dispose()


@pytest.mark.asyncio
async def test_uncovered_is_reported_but_never_stamped():
    app, session, engine = _make_app()
    _scan(session, "scan-old")
    _scan(session, "scan-new", when=NOW + timedelta(hours=1))
    _evidence(session, "scan-new", "ev-new", "AES", "src/other.py", 256)  # file not observed
    _resolved_event(session, "evt-3", "scan-old")
    session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
        r = await ac.post("/api/v1/drift/evaluate-verification",
                          json={"scan_id": "scan-new"})
    assert r.status_code == 200
    assert r.json()["counts"] == {"UNCOVERED": 1}
    session.expire_all()
    row = session.get(DriftEvent, "evt-3")
    assert row.verification_status is None  # no verdict recorded
    assert row.verified_by_scan_id is None
    engine.dispose()


@pytest.mark.asyncio
async def test_other_targets_and_later_resolutions_are_excluded():
    app, session, engine = _make_app()
    _scan(session, "scan-old", target="local://repo")
    _scan(session, "scan-other", target="local://different-repo")
    _scan(session, "scan-new", target="local://repo", when=NOW + timedelta(hours=1))
    _evidence(session, "scan-new", "ev-new", "AES", "src/other.py", 256)
    # same-target event resolved BEFORE the new scan -> eligible
    _resolved_event(session, "evt-keep", "scan-old")
    # different target -> excluded
    _resolved_event(session, "evt-other-target", "scan-other")
    # resolved AFTER the new scan ended -> excluded (not yet verifiable)
    session.add(DriftEvent(
        id="evt-late", current_scan_id="scan-old", detected_at=NOW - timedelta(days=3),
        drift_type="CHANGED", severity="HIGH",
        drift_details={"current_finding": {"algorithm": "RSA", "file_path": "src/k.py",
                                           "key_size": 1024}},
        resolution_status="RESOLVED", resolved_by="admin",
        resolved_at=NOW + timedelta(hours=2), resolution_notes="later",
    ))
    session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
        r = await ac.post("/api/v1/drift/evaluate-verification",
                          json={"scan_id": "scan-new"})
    assert r.status_code == 200
    ids = [v["drift_id"] for v in r.json()["verdicts"]]
    assert ids == ["evt-keep"]
    engine.dispose()


@pytest.mark.asyncio
async def test_unknown_scan_is_404():
    app, session, engine = _make_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
        r = await ac.post("/api/v1/drift/evaluate-verification",
                          json={"scan_id": "scan-missing"})
    assert r.status_code == 404
    engine.dispose()


@pytest.mark.asyncio
async def test_list_response_carries_verification_fields():
    app, session, engine = _make_app()
    _scan(session, "scan-old")
    _scan(session, "scan-new", when=NOW + timedelta(hours=1))
    _evidence(session, "scan-new", "ev-new", "RSA", "src/k.py", 4096)
    _resolved_event(session, "evt-4", "scan-old")
    session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
        await ac.post("/api/v1/drift/evaluate-verification",
                      json={"scan_id": "scan-new"})
        listed = await ac.get("/api/v1/drift?page=1&page_size=10")
    assert listed.status_code == 200, listed.text
    events = listed.json()["events"]
    target = [e for e in events if e["drift_id"] == "evt-4"][0]
    assert target["verification_status"] == "VERIFIED"
    assert target["verified_by_scan_id"] == "scan-new"
    assert target["verified_at"]
    engine.dispose()


@pytest.mark.asyncio
async def test_other_tenants_events_are_never_verified():
    app, session, engine = _make_app()
    _scan(session, "scan-old", target="local://repo")  # platform estate
    _scan(session, "scan-new", target="local://repo", when=NOW + timedelta(hours=1))
    _evidence(session, "scan-new", "ev-new", "AES", "src/other.py", 256)
    # same target string, DIFFERENT tenant — must not be verified by scan-new
    session.add(DriftEvent(
        id="evt-tenant-b", tenant_id="tenant-b", current_scan_id="scan-old",
        detected_at=NOW - timedelta(days=3), drift_type="CHANGED", severity="HIGH",
        drift_details={"current_finding": {"algorithm": "RSA", "file_path": "src/k.py",
                                           "key_size": 1024}},
        resolution_status="RESOLVED", resolved_by="admin",
        resolved_at=NOW - timedelta(days=1), resolution_notes="other tenant",
    ))
    session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as ac:
        r = await ac.post("/api/v1/drift/evaluate-verification",
                          json={"scan_id": "scan-new"})
    assert r.status_code == 200
    assert r.json()["verdicts"] == []  # tenant-b's event invisible to this scan
    session.expire_all()
    row = session.get(DriftEvent, "evt-tenant-b")
    assert row.verification_status is None
    engine.dispose()
