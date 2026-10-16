"""Remediation task lifecycle + automatic verification (audit 62 / GAP-006).

End-to-end through the API: task created from real evidence → accepted →
completed → verified against rescan evidence, with the verdict persisted,
the task status driven by it, and every step audited as a platform event.
"""

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
from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan

NOW = datetime.now(timezone.utc)
TARGET = "git@github.com:acme/payments.git"


EVENTS: list[dict] = []


def _capture_event(event_type, detail, payload=None, **kwargs):
    EVENTS.append({"event_type": event_type, "detail": detail, "payload": payload or {}})
    return None


@pytest.fixture(autouse=True)
def _capture_platform_events(monkeypatch):
    EVENTS.clear()
    monkeypatch.setattr("api.routers.remediation.emit_platform_event", _capture_event)
    yield
    EVENTS.clear()


def _make_app(current_user: str = "engineer-1", auditor: bool = False):
    import os

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
    app.dependency_overrides[require_auditor] = lambda: current_user
    return app, session, EVENTS


def _scan(session, scan_id: str, status: str = "COMPLETED", when=None) -> Scan:
    row = Scan(id=scan_id, scan_start=when or NOW, scan_end=when or NOW,
               target_type="GIT_REPOSITORY", target_location=TARGET, status=status)
    session.add(row)
    return row


def _evidence(session, eid: str, scan_id: str, algorithm: str, status: str = "FAIL",
              file_path: str = "src/payments/CardCipher.java", line: int = 42, **extra) -> EvidenceRecord:
    row = EvidenceRecord(id=eid, scan_id=scan_id, algorithm=algorithm,
                         compliance_status=status, file_path=file_path,
                         line_number=line, purpose=extra.get("purpose", "ENCRYPTION"),
                         key_size=extra.get("key_size"), mode=extra.get("mode"),
                         is_hardcoded_key=extra.get("is_hardcoded_key", False),
                         content_hash=f"hash-{eid}", chain_hash=f"chain-{eid}",
                         chain_position=1, confidence="HIGH", finding_data={})
    session.add(row)
    return row


def _client(app):
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


@pytest.mark.asyncio
async def test_full_lifecycle_verified_end_to_end():
    app, session, events = _make_app(current_user="auditor-1")
    _scan(session, "scan-1", when=NOW - timedelta(hours=2))
    _scan(session, "scan-2", when=NOW - timedelta(hours=1))  # the rescan
    _evidence(session, "e1", "scan-1", "DES", key_size=56)
    _evidence(session, "e2", "scan-2", "AES-256-GCM", status="PASS")
    session.commit()

    async with _client(app) as client:
        created = await client.post("/api/v1/remediation/tasks",
                                    json={"evidence_id": "e1", "owner": "pay-team"})
        assert created.status_code == 200, created.text
        task = created.json()
        assert task["status"] == "PROPOSED"
        assert task["rule_id"] == "replace-des"
        assert task["original_finding"]["algorithm"] == "DES"
        assert task["target_location"] == TARGET

        accepted = await client.post(f"/api/v1/remediation/tasks/{task['id']}/accept")
        assert accepted.status_code == 200
        assert accepted.json()["status"] == "ACCEPTED"

        completed = await client.post(f"/api/v1/remediation/tasks/{task['id']}/complete", json={})
        assert completed.status_code == 200, completed.text
        body = completed.json()
        # auto-verification picked the later scan of the same target
        assert body["status"] == "VERIFIED"
        assert body["latest_verification"]["result"] == "VERIFIED"
        assert body["latest_verification"]["rescan_id"] == "scan-2"

        listed = await client.get("/api/v1/remediation/verifications?task_id=" + task["id"])
        assert listed.status_code == 200
        assert listed.json()["total"] == 1

    assert {e["event_type"] for e in events} >= {
        "remediation.task_created", "remediation.task_accepted",
        "remediation.task_completed", "remediation.task_verified"}


@pytest.mark.asyncio
async def test_complete_without_rescan_is_inconclusive_and_keeps_completed():
    app, session, _ = _make_app()
    _scan(session, "scan-1", when=NOW - timedelta(hours=3))
    _evidence(session, "e1", "scan-1", "DES", key_size=56)
    session.commit()
    async with _client(app) as client:
        task = (await client.post("/api/v1/remediation/tasks", json={"evidence_id": "e1"})).json()
        completed = await client.post(f"/api/v1/remediation/tasks/{task['id']}/complete", json={})
        body = completed.json()
        assert body["latest_verification"]["result"] == "INCONCLUSIVE"
        assert body["status"] == "COMPLETED"  # evidence missing, not work missing


@pytest.mark.asyncio
async def test_regression_flips_verified_task_to_regression():
    app, session, _ = _make_app()
    _scan(session, "scan-1", when=NOW - timedelta(hours=3))
    _scan(session, "scan-2", when=NOW - timedelta(hours=1))
    _evidence(session, "e1", "scan-1", "DES", key_size=56)
    # rescan: original site fixed but a fresh RC4 violation appeared next to it
    _evidence(session, "e2", "scan-2", "AES-256-GCM", status="PASS")
    _evidence(session, "e3", "scan-2", "RC4", line=99)
    session.commit()
    async with _client(app) as client:
        task = (await client.post("/api/v1/remediation/tasks", json={"evidence_id": "e1"})).json()
        completed = await client.post(f"/api/v1/remediation/tasks/{task['id']}/complete", json={})
        body = completed.json()
        assert body["status"] == "REGRESSION"
        assert body["latest_verification"]["result"] == "REGRESSION"
        new_violations = (await client.get(
            f"/api/v1/remediation/tasks/{task['id']}")).json()
        assert new_violations["latest_verification"]["result"] == "REGRESSION"


@pytest.mark.asyncio
async def test_unchanged_finding_is_failed():
    app, session, _ = _make_app()
    _scan(session, "scan-1", when=NOW - timedelta(hours=3))
    _scan(session, "scan-2", when=NOW - timedelta(hours=1))
    _evidence(session, "e1", "scan-1", "DES", key_size=56)
    _evidence(session, "e2", "scan-2", "DES", key_size=56)
    session.commit()
    async with _client(app) as client:
        task = (await client.post("/api/v1/remediation/tasks", json={"evidence_id": "e1"})).json()
        body = (await client.post(f"/api/v1/remediation/tasks/{task['id']}/complete", json={})).json()
        assert body["status"] == "FAILED"
        assert body["latest_verification"]["result"] == "FAILED"


@pytest.mark.asyncio
async def test_verify_rejects_mismatched_rescan_target():
    app, session, _ = _make_app()
    _scan(session, "scan-1", when=NOW - timedelta(hours=3))
    _evidence(session, "e1", "scan-1", "DES", key_size=56)
    # a scan of a DIFFERENT repository
    session.add(Scan(id="scan-other", scan_start=NOW, target_type="GIT_REPOSITORY",
                     target_location="git@github.com:acme/other.git", status="COMPLETED"))
    session.commit()
    async with _client(app) as client:
        task = (await client.post("/api/v1/remediation/tasks", json={"evidence_id": "e1"})).json()
        await client.post(f"/api/v1/remediation/tasks/{task['id']}/accept")
        await client.post(f"/api/v1/remediation/tasks/{task['id']}/complete", json={})
        mismatch = await client.post(f"/api/v1/remediation/tasks/{task['id']}/verify",
                                     json={"rescan_id": "scan-other"})
        assert mismatch.status_code == 400
        assert "does not match" in mismatch.json()["detail"]


@pytest.mark.asyncio
async def test_reverify_after_fix_records_history():
    app, session, _ = _make_app()
    _scan(session, "scan-1", when=NOW - timedelta(hours=3))
    _scan(session, "scan-2", when=NOW - timedelta(hours=2))  # still broken
    _scan(session, "scan-3", when=NOW - timedelta(hours=1))  # fixed later
    _evidence(session, "e1", "scan-1", "DES", key_size=56)
    _evidence(session, "e2", "scan-2", "DES", key_size=56)
    _evidence(session, "e3", "scan-3", "AES-256-GCM", status="PASS")
    session.commit()
    async with _client(app) as client:
        task = (await client.post("/api/v1/remediation/tasks", json={"evidence_id": "e1"})).json()
        # verified against an explicitly chosen still-broken rescan first
        first = (await client.post(f"/api/v1/remediation/tasks/{task['id']}/complete",
                                   json={"rescan_id": "scan-2"})).json()
        assert first["latest_verification"]["result"] == "FAILED"
        # later re-verification against the fixed scan flips the verdict
        second = (await client.post(f"/api/v1/remediation/tasks/{task['id']}/verify",
                                    json={"rescan_id": "scan-3"})).json()
        assert second["status"] == "VERIFIED"
        history = await client.get(f"/api/v1/remediation/verifications?task_id={task['id']}")
        assert history.json()["total"] == 2  # both proofs retained


@pytest.mark.asyncio
async def test_task_not_found_and_bad_transitions():
    app, session, _ = _make_app()
    async with _client(app) as client:
        assert (await client.get("/api/v1/remediation/tasks/nope")).status_code == 404
        assert (await client.post("/api/v1/remediation/tasks",
                                  json={"evidence_id": "nope"})).status_code == 404
        # completing a task straight from PROPOSED is allowed (small teams) but
        # accepting a COMPLETED task is not
        _scan(session, "scan-1")
        _evidence(session, "e1", "scan-1", "DES", key_size=56)
        session.commit()
        task = (await client.post("/api/v1/remediation/tasks", json={"evidence_id": "e1"})).json()
        await client.post(f"/api/v1/remediation/tasks/{task['id']}/complete", json={})
        again = await client.post(f"/api/v1/remediation/tasks/{task['id']}/accept")
        assert again.status_code == 409


@pytest.mark.asyncio
async def test_tasks_filter_by_evidence_id_the_finding_cross_link():
    """§5 (round 73): the finding→task cross-link — `?evidence_id=`
    returns exactly the tasks referencing THAT finding, so the Findings
    drawer can show what an operator already owns on it."""
    app, session, _ = _make_app()
    _scan(session, "scan-1")
    _evidence(session, "e1", "scan-1", "DES", key_size=56)
    _evidence(session, "e2", "scan-1", "3DES", key_size=112)
    session.commit()
    async with _client(app) as client:
        t1 = (await client.post("/api/v1/remediation/tasks", json={"evidence_id": "e1"})).json()
        t2 = (await client.post("/api/v1/remediation/tasks", json={"evidence_id": "e2"})).json()

        both = await client.get("/api/v1/remediation/tasks")
        assert both.json()["total"] == 2

        only_e1 = await client.get("/api/v1/remediation/tasks", params={"evidence_id": "e1"})
        assert only_e1.status_code == 200, only_e1.text
        body = only_e1.json()
        assert body["total"] == 1
        assert [t["id"] for t in body["tasks"]] == [t1["id"]]
        assert body["tasks"][0]["evidence_id"] == "e1"
        assert t2["id"] not in [t["id"] for t in body["tasks"]]

        none = await client.get("/api/v1/remediation/tasks",
                                params={"evidence_id": "e-does-not-exist"})
        assert none.json()["total"] == 0
        assert none.json()["tasks"] == []

        # composes with the status filter
        accepted = await client.post(f"/api/v1/remediation/tasks/{t2['id']}/accept")
        assert accepted.status_code == 200
        combo = await client.get("/api/v1/remediation/tasks",
                                 params={"evidence_id": "e2", "status": "ACCEPTED"})
        assert combo.json()["total"] == 1
        assert combo.json()["tasks"][0]["id"] == t2["id"]
        wrong_status = await client.get("/api/v1/remediation/tasks",
                                        params={"evidence_id": "e2", "status": "PROPOSED"})
        assert wrong_status.json()["total"] == 0
