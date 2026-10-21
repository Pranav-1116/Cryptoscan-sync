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
    EVENTS.append({"event_type": event_type, "detail": detail, "payload": payload or {},
                   "kwargs": kwargs})
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
async def test_legacy_lifecycle_does_not_verify_pre_action_scan():
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
        # Later than baseline is insufficient: this scan predates the action.
        assert body["status"] == "COMPLETED"
        assert body["latest_verification"]["result"] == "INCONCLUSIVE"
        assert body["latest_verification"]["rescan_id"] is None

        listed = await client.get("/api/v1/remediation/verifications?task_id=" + task["id"])
        assert listed.status_code == 200
        assert listed.json()["total"] == 1

    assert {e["event_type"] for e in events} >= {
        "remediation.task_created", "remediation.task_accepted",
        "remediation.task_completed", "remediation.task_verified"}


@pytest.mark.asyncio
async def test_task_created_event_rides_the_request_session():
    """Round 81: the audit event must share the task's transaction.

    ``POST /remediation/tasks`` created the row on the request's session (which
    the FastAPI dependency commits) and then emitted on a *second* connection.
    On SQLite — the documented single-box backend — that is a writer-vs-writer
    conflict: the emit waited out busy_timeout and dropped the event with
    ``platform_event_persist_failed``, so an operator-loop drill found five
    accepted and five completed tasks and **zero** ``remediation.task_created``
    rows. The proposal step of the audit trail was silently missing.
    """
    app, session, events = _make_app()
    _scan(session, "scan-1")
    _evidence(session, "e1", "scan-1", "DES", key_size=56)
    session.commit()
    async with _client(app) as client:
        created = await client.post("/api/v1/remediation/tasks", json={"evidence_id": "e1"})
        assert created.status_code == 200, created.text
    emitted = [e for e in events if e["event_type"] == "remediation.task_created"]
    assert len(emitted) == 1
    assert emitted[0]["kwargs"].get("session") is session, (
        "the event must be written on the caller's session, not a second connection")


@pytest.mark.asyncio
async def test_complete_without_rescan_is_inconclusive_and_keeps_completed():
    app, session, _ = _make_app()
    _scan(session, "scan-1", when=NOW - timedelta(hours=3))
    _evidence(session, "e1", "scan-1", "DES", key_size=56)
    session.commit()
    async with _client(app) as client:
        task = (await client.post("/api/v1/remediation/tasks", json={"evidence_id": "e1"})).json()
        await client.post(f"/api/v1/remediation/tasks/{task['id']}/accept")
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
        await client.post(f"/api/v1/remediation/tasks/{task['id']}/accept")
        completed = await client.post(f"/api/v1/remediation/tasks/{task['id']}/complete", json={})
        body = completed.json()
        assert body["status"] == "COMPLETED"
        scan = session.get(Scan, "scan-2")
        scan.scan_start = scan.scan_end = datetime.now(timezone.utc)
        session.commit()
        body = (await client.post(f"/api/v1/remediation/tasks/{task['id']}/verify", json={"rescan_id": "scan-2"})).json()
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
        await client.post(f"/api/v1/remediation/tasks/{task['id']}/accept")
        await client.post(f"/api/v1/remediation/tasks/{task['id']}/complete", json={})
        scan = session.get(Scan, "scan-2")
        scan.scan_start = scan.scan_end = datetime.now(timezone.utc)
        session.commit()
        body = (await client.post(f"/api/v1/remediation/tasks/{task['id']}/verify", json={"rescan_id": "scan-2"})).json()
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
        await client.post(f"/api/v1/remediation/tasks/{task['id']}/accept")
        # Old explicit rescan is inconclusive, not an action verification.
        first = (await client.post(f"/api/v1/remediation/tasks/{task['id']}/complete",
                                   json={"rescan_id": "scan-2"})).json()
        assert first["latest_verification"]["result"] == "INCONCLUSIVE"
        scan = session.get(Scan, "scan-2")
        scan.scan_start = scan.scan_end = datetime.now(timezone.utc)
        session.commit()
        observed = (await client.post(f"/api/v1/remediation/tasks/{task['id']}/verify", json={"rescan_id": "scan-2"})).json()
        assert observed["latest_verification"]["result"] == "FAILED"
        scan = session.get(Scan, "scan-3")
        scan.scan_start = scan.scan_end = datetime.now(timezone.utc)
        session.commit()
        # A later favorable comparison still lacks an approved condition.
        second = (await client.post(f"/api/v1/remediation/tasks/{task['id']}/verify",
                                    json={"rescan_id": "scan-3"})).json()
        assert second["status"] == "COMPLETED"
        assert second["latest_verification"]["result"] == "INCONCLUSIVE"
        assert "approved assurance" in second["latest_verification"]["reason"]
        history = await client.get(f"/api/v1/remediation/verifications?task_id={task['id']}")
        assert history.json()["total"] == 3  # all comparisons retained


@pytest.mark.asyncio
async def test_task_not_found_and_bad_transitions():
    app, session, _ = _make_app()
    async with _client(app) as client:
        assert (await client.get("/api/v1/remediation/tasks/nope")).status_code == 404
        assert (await client.post("/api/v1/remediation/tasks",
                                  json={"evidence_id": "nope"})).status_code == 404
        # No proposed-task completion bypass; completed tasks cannot re-accept.
        _scan(session, "scan-1")
        _evidence(session, "e1", "scan-1", "DES", key_size=56)
        session.commit()
        task = (await client.post("/api/v1/remediation/tasks", json={"evidence_id": "e1"})).json()
        denied = await client.post(f"/api/v1/remediation/tasks/{task['id']}/complete", json={})
        assert denied.status_code == 409
        await client.post(f"/api/v1/remediation/tasks/{task['id']}/accept")
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


@pytest.mark.asyncio
async def test_tasks_filter_by_asset_id_through_the_stored_link_table():
    """§5 (round 75): the asset→task cross-link. Tasks reference evidence
    records; assets reference evidence through the PERSISTED
    crypto_asset_evidence link table — the join goes through that stored
    linkage, never a re-derived identity guess."""
    from db.models.crypto_asset import CryptoAsset
    from db.models.crypto_asset_evidence import CryptoAssetEvidence

    app, session, _ = _make_app()
    _scan(session, "scan-1")
    _evidence(session, "e1", "scan-1", "DES", key_size=56)
    _evidence(session, "e2", "scan-1", "3DES", key_size=112)
    asset = CryptoAsset(algorithm="DES", file_path="src/payments/CardCipher.java",
                        asset_key="spine-des-cardcipher", line_number=0)
    session.add(asset)
    session.flush()
    # the stored linkage: asset ↔ e1 only (e2 stays unlinked)
    session.add(CryptoAssetEvidence(asset_id=asset.id, evidence_id="e1"))
    session.commit()
    async with _client(app) as client:
        t1 = (await client.post("/api/v1/remediation/tasks", json={"evidence_id": "e1"})).json()
        t2 = (await client.post("/api/v1/remediation/tasks", json={"evidence_id": "e2"})).json()

        by_asset = await client.get("/api/v1/remediation/tasks",
                                    params={"asset_id": asset.id})
        assert by_asset.status_code == 200, by_asset.text
        body = by_asset.json()
        assert body["total"] == 1
        assert [t["id"] for t in body["tasks"]] == [t1["id"]]
        assert body["tasks"][0]["evidence_id"] == "e1"
        assert t2["id"] not in [t["id"] for t in body["tasks"]]

        # an asset with NO linked evidence answers empty — unknown, not zero
        orphan = CryptoAsset(algorithm="RC4", file_path="src/legacy/Old.java",
                             asset_key="spine-rc4-old", line_number=0)
        session.add(orphan)
        session.commit()
        empty = await client.get("/api/v1/remediation/tasks",
                                 params={"asset_id": orphan.id})
        assert empty.json()["total"] == 0
        assert empty.json()["tasks"] == []

        # composes with the status filter
        await client.post(f"/api/v1/remediation/tasks/{t1['id']}/accept")
        combo = await client.get("/api/v1/remediation/tasks",
                                 params={"asset_id": asset.id, "status": "ACCEPTED"})
        assert combo.json()["total"] == 1
        assert combo.json()["tasks"][0]["id"] == t1["id"]
        wrong = await client.get("/api/v1/remediation/tasks",
                                 params={"asset_id": asset.id, "status": "PROPOSED"})
        assert wrong.json()["total"] == 0
