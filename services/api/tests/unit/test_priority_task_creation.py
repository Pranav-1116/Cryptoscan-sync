"""POST /api/v1/priority/{ref_id}/tasks — priority item → owned remediation task(s).

§4.7 gap closure (round 42): the ranked queue must be actionable. Drift-sourced
items open tasks via the same auto-open path the drift ack uses — a task always
points at an EvidenceRecord, never at a rank number. Runtime-sourced items are
refused honestly: they have no evidence record, and tasks require one for
later verification.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register all tables
from api.dependencies import get_current_user, get_db_session, require_auditor
from api.main import create_app
from db.connection.session import Base

NOW = datetime(2026, 10, 13, tzinfo=timezone.utc)


def _make_app():
    import os

    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SECRET_KEY", "priority-tasks-" + "z" * 20)
    from api.config.settings import get_settings

    get_settings.cache_clear()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    app = create_app()
    app.dependency_overrides[get_db_session] = lambda: (yield session)
    app.dependency_overrides[get_current_user] = lambda: "soc"
    app.dependency_overrides[require_auditor] = lambda: "soc"
    return app, session, engine


def _scan(session, scan_id: str):
    from db.models.scan import Scan

    session.add(Scan(id=scan_id, scan_start=NOW, scan_end=NOW,
                     target_type="GIT_REPOSITORY", target_location=f"git@acme:{scan_id}.git",
                     status="COMPLETED"))


def _evidence(session, eid: str, scan_id: str, algorithm: str, status: str = "FAIL"):
    from db.models.evidence_record import EvidenceRecord

    session.add(EvidenceRecord(
        id=eid, scan_id=scan_id, algorithm=algorithm, compliance_status=status,
        file_path="src/pay/CardCipher.java", line_number=42, purpose="ENCRYPTION",
        content_hash=f"hash-{eid}", chain_hash=f"chain-{eid}", chain_position=1,
        confidence="HIGH", finding_data={},
        policy_evaluation={"rules_evaluated": [{"rule_id": "KR-001"}]}))


def _drift(session, drift_id: str, scan_id: str, algorithm: str = "3DES"):
    from db.models.drift_event import DriftEvent

    session.add(DriftEvent(
        id=drift_id, current_scan_id=scan_id, detected_at=NOW,
        drift_type="ALGORITHM_WEAKENED", severity="HIGH",
        drift_details={"change_type": "ALGORITHM_WEAKENED", "reason": "3DES reintroduced",
                       "algorithm": algorithm},
        resolution_status="OPEN"))


@pytest.mark.asyncio
async def test_drift_item_opens_owned_tasks_pointing_at_evidence():
    app, session, engine = _make_app()
    _scan(session, "scan-1")
    _evidence(session, "ev-1", "scan-1", "3DES")
    _evidence(session, "ev-2", "scan-1", "3DES", status="WARN")
    _evidence(session, "ev-3", "scan-1", "AES-256-GCM")  # different algorithm — excluded
    _drift(session, "drift-1", "scan-1")
    session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post("/api/v1/priority/drift-1/tasks", json={"owner": "crypto-team"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["source"] == "drift" and body["owner"] == "crypto-team"
    assert body["created"] == 2, "only FAIL/WARN evidence for the drifted algorithm"
    assert len(body["task_ids"]) == 2
    assert "PROPOSED" in body["message"]

    from db.models.remediation_task import RemediationTask

    tasks = session.query(RemediationTask).all()
    assert {t.evidence_id for t in tasks} == {"ev-1", "ev-2"}, "tasks point at evidence, not ranks"
    assert all(t.source == "drift" and t.source_ref == "drift-1" for t in tasks)
    assert all(t.owner == "crypto-team" and t.status == "PROPOSED" for t in tasks)
    engine.dispose()


@pytest.mark.asyncio
async def test_drift_item_without_failing_evidence_creates_nothing_and_says_so():
    app, session, engine = _make_app()
    _scan(session, "scan-2")
    _evidence(session, "ev-ok", "scan-2", "AES-256-GCM", status="PASS")
    _drift(session, "drift-clean", "scan-2", algorithm="3DES")  # no 3DES evidence rows
    session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post("/api/v1/priority/drift-clean/tasks", json={})
    assert r.status_code == 200
    body = r.json()
    assert body["created"] == 0 and body["task_ids"] == []
    assert "No task opened" in body["message"], "honest no-op, not a hollow task"
    engine.dispose()


@pytest.mark.asyncio
async def test_runtime_item_is_refused_honestly():
    app, session, engine = _make_app()
    from db.models.runtime_finding import RuntimeFinding

    session.add(RuntimeFinding(
        id="rf-1", scanner_id="netmon", hostname="edge.acme.internal",
        process_name="nginx", algorithm="TLS_RSA_WITH_AES_128_CBC_SHA",
        weak_tls=True, status="RISK", observation_count=3, dedup_key="netmon:edge:nginx:cbc",
        last_seen_at=NOW))
    session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        r = await c.post("/api/v1/priority/rf-1/tasks", json={"owner": "infra"})
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert "evidence_id" in detail and "re-scan" in detail.lower()
    engine.dispose()


@pytest.mark.asyncio
async def test_unknown_ref_is_404_and_body_is_optional():
    app, session, engine = _make_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        assert (await c.post("/api/v1/priority/nope/tasks", json={"owner": "x"})).status_code == 404
        # no JSON body at all must not 422 on parsing — owner stays unassigned
        assert (await c.post("/api/v1/priority/nope/tasks")).status_code == 404
    engine.dispose()
