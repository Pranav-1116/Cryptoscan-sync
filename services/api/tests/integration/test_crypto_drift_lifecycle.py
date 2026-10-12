"""Real SQLite transaction: approved baseline -> scan delta -> disposition.

RESOLVED is an auditor disposition, not a claim that remediation is VERIFIED.
The verification scan in this test is a separate evidence-backed observation.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 - register tables
from api.config.settings import get_settings
from api.dependencies import get_current_user, get_db_session, require_auditor
from api.main import create_app
from db.connection.session import Base
from db.models.baseline import Baseline
from db.models.drift_event import DriftEvent
from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan
from db.models.user import User
from db.repositories.baseline_repository import BaselineRepository
from db.repositories.drift_repository import DriftRepository
from db.tenancy import tenant_scope
from worker.pipeline.pipeline_runner import PipelineContext, PipelineRunner
from worker.pipeline.stage_drift import execute as execute_standalone_drift

TARGET = "https://example.test/crypto.git"
NOW = datetime(2026, 10, 12, tzinfo=timezone.utc)
BASELINE = [("AES", "secure.py", 1), ("RSA", "gone.py", 3)]
DELTA = [("DES", "secure.py", 1), ("MD5", "new.py", 2)]


@pytest.fixture
def lifecycle_db(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("SECRET_KEY", "crypto-drift-test-" + "z" * 24)
    get_settings.cache_clear()
    engine = create_engine(
        "sqlite+pysqlite:///:memory:", connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    with factory() as db:
        db.add(User(username="aud", roles="auditor", password_hash="x"))
        db.commit()
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: "aud"
    app.dependency_overrides[require_auditor] = lambda: "aud"

    def session_dependency():
        with factory() as db:
            yield db

    app.dependency_overrides[get_db_session] = session_dependency
    yield factory, app
    engine.dispose()


def seed_scan(db, scan_id, findings, *, tenant_id=None, target=TARGET):
    db.add(Scan(
        id=scan_id, tenant_id=tenant_id, scan_start=NOW,
        scan_end=NOW, target_location=target, status="COMPLETED",
    ))
    for i, (algorithm, path, line) in enumerate(findings):
        db.add(EvidenceRecord(
            id=f"{scan_id}-e{i}", tenant_id=tenant_id, scan_id=scan_id,
            content_hash="a" * 64, chain_hash="b" * 64, chain_position=i,
            algorithm=algorithm, confidence="HIGH", file_path=path,
            line_number=line, finding_data={}, compliance_status="PASS",
        ))
    db.commit()


def compare(db, scan_id):
    ctx = PipelineContext(
        job_id=f"job-{scan_id}", target_repo=TARGET, target_branch="main",
        triggered_by="test", workspace_dir="/tmp", scan_id=scan_id,
    )
    PipelineRunner.__new__(PipelineRunner)._drift(ctx, db)
    db.commit()
    return ctx


@pytest.mark.asyncio
async def test_approved_baseline_change_ack_verification_and_resolution(lifecycle_db):
    factory, app = lifecycle_db
    transport = ASGITransport(app=app)
    with factory() as db:
        seed_scan(db, "scan-base", BASELINE)
        no_baseline = compare(db, "scan-base")
        assert no_baseline.scan_meta["baseline_comparison"] == "NO_APPROVED_BASELINE"
        assert db.get(Scan, "scan-base").statistics["baseline_comparison"] == "NO_APPROVED_BASELINE"
        assert no_baseline.drift_events == []
        assert db.query(DriftEvent).count() == 0
        proposal = db.scalar(select(Baseline).where(Baseline.status == "PROPOSED"))
        assert proposal is not None
        assert BaselineRepository(db).get_active(TARGET) is None

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        approved = await client.post(f"/api/v1/baselines/{proposal.id}/approve-proposed", json={})
        assert approved.status_code == 200, approved.text
        assert approved.json()["status"] == "ACTIVE"

        with factory() as db:
            seed_scan(db, "scan-delta", DELTA)
            ctx = compare(db, "scan-delta")
            assert ctx.scan_meta["baseline_comparison"] == "COMPARED"
            assert {e["drift_type"] for e in ctx.drift_events} == {"NEW", "REMOVED", "CHANGED"}
            rows = db.scalars(select(DriftEvent).where(DriftEvent.current_scan_id == "scan-delta")).all()
            assert len(rows) == 3
            assert all(r.baseline_id == proposal.id for r in rows)
            changed = next(r for r in rows if r.drift_type == "CHANGED")
            removed_id = next(r.id for r in rows if r.drift_type == "REMOVED")
            assert changed.drift_details["baseline_finding"]["algorithm"] == "AES"
            assert changed.drift_details["baseline_finding"]["evidence_id"] == "scan-base-e0"
            assert changed.drift_details["current_finding"]["algorithm"] == "DES"
            assert changed.drift_details["current_finding"]["evidence_id"] == "scan-delta-e0"
            event_id = changed.id
            initial_detected_at = changed.detected_at
            retry = compare(db, "scan-delta")
            assert retry.drift_events == []
            standalone = PipelineContext(
                job_id="job-retry", target_repo=TARGET, target_branch="main",
                triggered_by="test", workspace_dir="/tmp", scan_id="scan-delta",
            )
            assert execute_standalone_drift(standalone, db) is standalone
            assert standalone.drift_events == []
            assert db.query(DriftEvent).filter_by(current_scan_id="scan-delta").count() == 3

        ack = await client.post(f"/api/v1/drift/{event_id}/acknowledge", json={"notes": "investigating"})
        assert ack.status_code == 200, ack.text
        assert ack.json()["acknowledged_by"] == "aud"
        assert ack.json()["acknowledged_at"] is not None
        assert ack.json()["resolved_at"] is None
        assert ack.json()["resolution_status"] == "ACKNOWLEDGED"
        # Administrative false-positive disposition is legitimate without a rescan,
        # but it is never represented as evidence-backed remediation verification.
        fp = await client.post(
            f"/api/v1/drift/{removed_id}/false-positive", json={"notes": "reviewed finding"}
        )
        assert fp.status_code == 200, fp.text
        assert fp.json()["resolution_status"] == "FALSE_POSITIVE"
        assert fp.json()["resolved_by"] == "aud"
        assert "VERIFIED" not in fp.json().values()

        with factory() as db:
            assert compare(db, "scan-delta").drift_events == []
            assert db.get(DriftEvent, event_id).resolution_status == "ACKNOWLEDGED"
            assert db.get(DriftEvent, removed_id).resolution_status == "FALSE_POSITIVE"
            # A verification observation is required before we claim the condition
            # cleared. The API does not turn acknowledgement into verification.
            assert db.get(DriftEvent, event_id).resolution_status == "ACKNOWLEDGED"
            seed_scan(db, "scan-verified", BASELINE)
            verified = compare(db, "scan-verified")
            assert verified.scan_meta["baseline_comparison"] == "COMPARED"
            assert verified.drift_events == []
            assert db.get(DriftEvent, event_id).resolution_status == "ACKNOWLEDGED"

        resolved = await client.post(f"/api/v1/drift/{event_id}/resolve", json={"notes": "reviewed after rescan"})
        assert resolved.status_code == 200, resolved.text
        assert resolved.json()["resolution_status"] == "RESOLVED"
        assert resolved.json()["resolved_by"] == "aud"
        assert resolved.json()["resolved_at"] is not None
        assert resolved.json()["acknowledged_at"] == ack.json()["acknowledged_at"]

    with factory() as db:
        row = db.get(DriftEvent, event_id)
        assert row.detected_at == initial_detected_at
        seed_scan(db, "scan-return", [("DES", "secure.py", 1), ("RSA", "gone.py", 3)])
        recurring = compare(db, "scan-return")
        assert [event["drift_type"] for event in recurring.drift_events] == ["CHANGED"]
        assert db.scalar(select(DriftEvent).where(DriftEvent.current_scan_id == "scan-return")).id != event_id


def test_tenant_baseline_provenance_and_unavailable_reference(lifecycle_db):
    factory, _app = lifecycle_db
    with factory() as db:
        seed_scan(db, "a-base", BASELINE, tenant_id="tenant-a")
        seed_scan(db, "b-current", DELTA, tenant_id="tenant-b")
        db.add(Baseline(
            system_identifier=TARGET, environment="default", approved_scan_id="a-base",
            tenant_id="tenant-a", approved_by="aud", approved_at=NOW, status="ACTIVE",
        ))
        db.commit()
        result = compare(db, "b-current")
        assert result.scan_meta["baseline_comparison"] == "NO_APPROVED_BASELINE"
        assert db.query(DriftEvent).count() == 0
        # A same-tenant but invalid reference must also not yield an all-clear.
        seed_scan(db, "b-base", BASELINE, tenant_id="tenant-b")
        b = BaselineRepository(db).approve(
            system_identifier=TARGET, scan_id="b-base", approved_by="aud",
        )
        b.tenant_id = "tenant-b"  # worker's unscoped session represents this owner
        db.get(Scan, "b-base").status = "FAILED"
        db.commit()
        result = compare(db, "b-current")
        assert result.scan_meta["baseline_comparison"] == "BASELINE_UNAVAILABLE"
        assert db.get(Scan, "b-current").statistics["baseline_comparison"] == "BASELINE_UNAVAILABLE"
        assert db.query(DriftEvent).count() == 0


@pytest.mark.asyncio
async def test_ack_rolls_back_when_audit_is_unavailable(lifecycle_db, monkeypatch):
    from db.repositories.user_repository import UserRepository

    factory, app = lifecycle_db
    with factory() as db:
        seed_scan(db, "audit-scan", DELTA)
        db.add(DriftEvent(
            id="audit-event", current_scan_id="audit-scan", detected_at=NOW,
            drift_type="CHANGED", severity="HIGH", resolution_status="OPEN",
        ))
        db.commit()

    def audit_failure(*_args, **_kwargs):
        raise RuntimeError("audit unavailable")

    monkeypatch.setattr(UserRepository, "audit", audit_failure)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post("/api/v1/drift/audit-event/acknowledge", json={})
    assert response.status_code == 503
    with factory() as db:
        row = db.get(DriftEvent, "audit-event")
        assert row.resolution_status == "OPEN"
        assert row.acknowledged_at is None


def test_partial_config_comparison_is_not_reported_as_complete(lifecycle_db, monkeypatch):
    from drift.core import config_detector

    factory, _app = lifecycle_db
    with factory() as db:
        seed_scan(db, "cfg-base", BASELINE)
        BaselineRepository(db).approve(
            system_identifier=TARGET, scan_id="cfg-base", approved_by="aud",
        )
        seed_scan(db, "cfg-current", DELTA)
        def unavailable(*_args, **_kwargs):
            raise RuntimeError("configuration comparison unavailable")
        monkeypatch.setattr(config_detector, "detect_config_drift", unavailable)
        result = compare(db, "cfg-current")
        assert result.scan_meta["baseline_comparison"] == "PARTIAL_CONFIG_UNAVAILABLE"
        assert db.get(Scan, "cfg-current").statistics["baseline_comparison"] == "PARTIAL_CONFIG_UNAVAILABLE"
        assert {e["drift_type"] for e in result.drift_events} == {"NEW", "REMOVED", "CHANGED"}


def test_tenant_cannot_dispose_another_or_legacy_drift(lifecycle_db):
    factory, _app = lifecycle_db
    with factory() as db:
        seed_scan(db, "a-scan", DELTA, tenant_id="tenant-a")
        seed_scan(db, "b-scan", DELTA, tenant_id="tenant-b")
        db.add_all([
            DriftEvent(
                id="a-event", tenant_id="tenant-a", current_scan_id="a-scan",
                detected_at=NOW, drift_type="CHANGED", severity="HIGH",
                resolution_status="OPEN",
            ),
            DriftEvent(
                id="platform-event", current_scan_id="a-scan",
                detected_at=NOW, drift_type="CHANGED", severity="HIGH",
                resolution_status="OPEN",
            ),
            DriftEvent(
                id="b-event", tenant_id="tenant-b", current_scan_id="b-scan",
                detected_at=NOW, drift_type="CHANGED", severity="HIGH",
                resolution_status="OPEN",
            ),
        ])
        db.commit()
        repo = DriftRepository(db)
        with tenant_scope("tenant-b"):
            assert repo.acknowledge("a-event", "bob") is None
            assert repo.resolve("platform-event", "bob") is None
            assert repo.acknowledge("b-event", "bob") is not None
        db.commit()
        assert db.get(DriftEvent, "a-event").resolution_status == "OPEN"
        assert db.get(DriftEvent, "platform-event").resolution_status == "OPEN"
        assert db.get(DriftEvent, "b-event").acknowledged_by == "bob"
