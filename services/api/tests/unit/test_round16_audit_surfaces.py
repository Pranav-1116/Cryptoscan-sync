"""Round-16 audit surfaces: policy rule overrides, drift->remediation
auto-linking, scan-queue backpressure (MAX_QUEUE_DEPTH), and optimistic
scan-job status locking (audits 03/04/05).

One file because they share the seeding idiom; each section is independent.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401
from api.dependencies import get_current_user, get_db_session, require_admin, require_auditor
from api.main import create_app
from db.connection.session import Base
from db.models.drift_event import DriftEvent
from db.models.evidence_record import EvidenceRecord
from db.models.policy_rule_override import PolicyRuleOverride
from db.models.remediation_task import RemediationTask
from db.models.scan import Scan
from db.models.scan_job import ScanJob
from db.repositories.job_repository import JobRepository

NOW = datetime.now(timezone.utc)


def _make_app(current_user: str = "auditor-1", admin: bool = True):
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
    if admin:
        app.dependency_overrides[require_admin] = lambda: current_user
    return app, session


def _client(app):
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


def _scan(session, scan_id: str, status: str = "COMPLETED") -> Scan:
    row = Scan(id=scan_id, scan_start=NOW, scan_end=NOW,
               target_type="GIT_REPOSITORY", target_location=f"git@acme:{scan_id}.git",
               status=status)
    session.add(row)
    return row


def _evidence(session, eid: str, scan_id: str, algorithm: str, status: str = "FAIL",
              file_path: str = "src/pay/CardCipher.java", line: int = 42) -> EvidenceRecord:
    row = EvidenceRecord(id=eid, scan_id=scan_id, algorithm=algorithm,
                         compliance_status=status, file_path=file_path, line_number=line,
                         purpose="ENCRYPTION", content_hash=f"hash-{eid}",
                         chain_hash=f"chain-{eid}", chain_position=1,
                         confidence="HIGH", finding_data={},
                         policy_evaluation={"rules_evaluated": [{"rule_id": "KR-001"}]})
    session.add(row)
    return row


def _drift(session, drift_id: str, scan_id: str, algorithm: str = "3DES") -> DriftEvent:
    row = DriftEvent(id=drift_id, current_scan_id=scan_id, detected_at=NOW,
                     drift_type="ALGORITHM_WEAKENED", severity="HIGH",
                     drift_details={"change_type": "ALGORITHM_WEAKENED",
                                    "reason": "3DES reintroduced",
                                    "algorithm": algorithm},
                     resolution_status="OPEN")
    session.add(row)
    return row


# --------------------------------------------------------------------------- #
# policy rule overrides (audit 05 — rule management surface)
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_policy_rules_listing_reports_override_and_effective_state():
    app, session = _make_app()
    async with _client(app) as c:
        r = await c.get("/api/v1/policy/rules")
        assert r.status_code == 200
        body = r.json()
        assert body["override_count"] == 0
        assert body["rules"], "pack must not be empty"
        first = body["rules"][0]
        assert first["pack_enabled"] == first["enabled"]
        assert first["override"] is None

        # one override, then the listing must reflect pack vs effective
        rule_id = first["rule_id"]
        session.add(PolicyRuleOverride(rule_id=rule_id, enabled=False,
                                       updated_by="admin-1"))
        session.commit()
        r2 = await c.get("/api/v1/policy/rules")
        assert r2.status_code == 200
        rules = {row["rule_id"]: row for row in r2.json()["rules"]}
        assert rules[rule_id]["override"]["enabled"] is False
        assert rules[rule_id]["enabled"] is False
        assert rules[rule_id]["pack_enabled"] is True, "pack row must stay untouched"


@pytest.mark.asyncio
async def test_policy_override_set_validate_and_clear():
    app, session = _make_app()
    async with _client(app) as c:
        r = await c.get("/api/v1/policy/rules")
        rule_id = r.json()["rules"][0]["rule_id"]

        # unknown rule -> 404
        r404 = await c.put("/api/v1/policy/rules/no-such-rule/override",
                           json={"enabled": True})
        assert r404.status_code == 404

        # bad severity -> 422
        r422 = await c.put(f"/api/v1/policy/rules/{rule_id}/override",
                           json={"enabled": True, "severity": "CATASTROPHIC"})
        assert r422.status_code == 422

        # set: disable + severity override
        r200 = await c.put(f"/api/v1/policy/rules/{rule_id}/override",
                           json={"enabled": False, "severity": "CRITICAL",
                                 "note": "accepted risk until Q3"})
        assert r200.status_code == 200
        assert r200.json()["override"]["enabled"] is False
        assert r200.json()["override"]["severity"] == "CRITICAL"

        # idempotent update path
        r201 = await c.put(f"/api/v1/policy/rules/{rule_id}/override",
                           json={"enabled": True, "severity": None})
        assert r201.status_code == 200
        assert r201.json()["override"]["enabled"] is True
        assert r201.json()["override"]["severity"] is None

        # clear -> pack behavior restored, second clear -> 404
        rdel = await c.delete(f"/api/v1/policy/rules/{rule_id}/override")
        assert rdel.status_code == 200
        assert rdel.json()["pack_behavior_restored"] is True
        assert (await c.delete(f"/api/v1/policy/rules/{rule_id}/override")).status_code == 404


def test_apply_overrides_mutates_engine_and_skips_unknown_rules():
    from pathlib import Path

    from policy.core.engine import PolicyEngine
    from policy.core.overrides import apply_overrides

    # same directory the router and the worker stage resolve to
    rules_dir = Path(__file__).resolve().parents[3] / "policy" / "rule_definitions"
    engine = PolicyEngine(str(rules_dir))
    assert engine.rule_set.rules
    target = engine.rule_set.rules[0]
    before_enabled = [r.rule_id for r in engine.evaluator.enabled_rules]
    assert target.rule_id in before_enabled

    class Row:
        def __init__(self, rule_id, enabled, severity):
            self.rule_id, self.enabled, self.severity = rule_id, enabled, severity

    stats = apply_overrides(engine, [
        Row(target.rule_id, False, "CRITICAL"),
        Row("does-not-exist", False, None),
    ])
    assert stats == {"applied": 1, "unknown_rule": 1}
    assert target.enabled is False
    assert target.severity == "CRITICAL"
    assert target.rule_id not in [r.rule_id for r in engine.evaluator.enabled_rules]


# --------------------------------------------------------------------------- #
# drift -> remediation auto-linking (audit 03)
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_drift_ack_auto_opens_remediation_tasks():
    app, session = _make_app()
    _scan(session, "scan-1")
    _evidence(session, "ev-1", "scan-1", "3DES")
    _evidence(session, "ev-2", "scan-1", "3DES", status="WARN", file_path="src/legacy/Des.java", line=7)
    _evidence(session, "ev-3", "scan-1", "AES-256-GCM")  # not the drifted algorithm
    _evidence(session, "ev-4", "scan-1", "3DES", status="PASS", file_path="src/ok/Ok.java", line=1)
    _drift(session, "drift-1", "scan-1", algorithm="3DES")
    session.commit()

    async with _client(app) as c:
        r = await c.post("/api/v1/drift/drift-1/acknowledge",
                         json={"create_remediation_tasks": True, "task_owner": "crypto-team"})
        assert r.status_code == 200
        body = r.json()
        assert body["resolution_status"] == "ACKNOWLEDGED"
        assert len(body["remediation_task_ids"]) == 2, "only FAIL/WARN evidence for 3DES"

        tasks = session.query(RemediationTask).all()
        assert {t.evidence_id for t in tasks} == {"ev-1", "ev-2"}
        assert all(t.source == "drift" for t in tasks)
        assert all(t.source_ref == "drift-1" for t in tasks)
        assert all(t.owner == "crypto-team" for t in tasks)
        assert all(t.status == "PROPOSED" for t in tasks)
        assert tasks[0].rule_id == "KR-001", "rule snapshotted from the evidence's evaluation"

        # the link is followable afterwards
        r2 = await c.get("/api/v1/drift/drift-1/remediation-tasks")
        assert r2.status_code == 200
        listed = r2.json()
        assert listed["drift_id"] == "drift-1"
        assert {t["evidence_id"] for t in listed["tasks"]} == {"ev-1", "ev-2"}

        # unknown drift id -> honest 404s
        assert (await c.get("/api/v1/drift/nope/remediation-tasks")).status_code == 404
        r3 = await c.post("/api/v1/drift/nope/acknowledge", json={})
        assert r3.status_code == 404


@pytest.mark.asyncio
async def test_drift_ack_without_flag_creates_no_tasks_and_clean_drift_creates_none():
    app, session = _make_app()
    _scan(session, "scan-2")
    _evidence(session, "ev-9", "scan-2", "3DES")
    _drift(session, "drift-2", "scan-2", algorithm="3DES")
    session.commit()

    async with _client(app) as c:
        r = await c.post("/api/v1/drift/drift-2/acknowledge", json={"notes": "seen"})
        assert r.status_code == 200
        assert r.json()["remediation_task_ids"] == []
        assert session.query(RemediationTask).count() == 0

        # honest no-op: drift on an algorithm with no failing evidence
        _drift(session, "drift-3", "scan-2", algorithm="AES-128-CBC")
        session.commit()
        r2 = await c.post("/api/v1/drift/drift-3/acknowledge",
                          json={"create_remediation_tasks": True})
        assert r2.status_code == 200
        assert r2.json()["remediation_task_ids"] == []


# --------------------------------------------------------------------------- #
# queue backpressure: MAX_QUEUE_DEPTH (audit 05)
# --------------------------------------------------------------------------- #

def test_admission_rejects_when_queue_at_capacity():
    import os

    from api.security import scan_admission

    app, _session = _make_app()

    # control-plane seams: no emergency stop, permissive policy, no OT
    # declaration — so the queue-depth gate is the only thing that can refuse
    orig_state = scan_admission._control_plane_state
    orig_ot = scan_admission._ot_declared
    orig_count = scan_admission._active_job_count
    orig_env = os.environ.get("MAX_QUEUE_DEPTH")
    scan_admission._control_plane_state = lambda: ([], None)
    scan_admission._ot_declared = lambda: False
    scan_admission._active_job_count = lambda: 501
    try:
        os.environ["MAX_QUEUE_DEPTH"] = "500"
        with pytest.raises(Exception) as excinfo:
            scan_admission.admit_scan(scan_mode="passive")
        assert getattr(excinfo.value, "status_code", None) == 429
        assert "MAX_QUEUE_DEPTH" in excinfo.value.detail

        # a disabled cap (<= 0) must not even count
        counted = {"n": 0}

        def counting_seam():
            counted["n"] += 1
            return 10_000

        scan_admission._active_job_count = counting_seam
        os.environ["MAX_QUEUE_DEPTH"] = "0"
        decision = scan_admission.admit_scan(scan_mode="passive")
        assert decision is not None
        assert counted["n"] == 0

        # below capacity: passes
        scan_admission._active_job_count = lambda: 499
        os.environ["MAX_QUEUE_DEPTH"] = "500"
        decision = scan_admission.admit_scan(scan_mode="passive")
        assert decision is not None
    finally:
        scan_admission._control_plane_state = orig_state
        scan_admission._ot_declared = orig_ot
        scan_admission._active_job_count = orig_count
        if orig_env is None:
            os.environ.pop("MAX_QUEUE_DEPTH", None)
        else:
            os.environ["MAX_QUEUE_DEPTH"] = orig_env


def test_admission_queue_depth_counts_only_active_jobs():
    """The count behind the gate sees QUEUED+RUNNING, never settled jobs."""
    from api.security.scan_admission import _count_active_jobs

    _, session = _make_app()
    session.add(ScanJob(id="j-1", job_type="MANUAL", target_repo="r", triggered_by="t", status="QUEUED"))
    session.add(ScanJob(id="j-2", job_type="MANUAL", target_repo="r", triggered_by="t", status="RUNNING"))
    session.add(ScanJob(id="j-3", job_type="MANUAL", target_repo="r", triggered_by="t", status="COMPLETED"))
    session.add(ScanJob(id="j-4", job_type="MANUAL", target_repo="r", triggered_by="t", status="FAILED"))
    session.commit()

    assert _count_active_jobs(session) == 2


# --------------------------------------------------------------------------- #
# optimistic scan-job locking (audit 04)
# --------------------------------------------------------------------------- #

def _job_session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def test_update_status_is_cas_and_increments_version():
    session = _job_session()
    repo = JobRepository(session)
    session.add(ScanJob(id="job-1", job_type="MANUAL", target_repo="r", triggered_by="t", status="QUEUED", version=0))
    session.commit()

    row = repo.update_status("job-1", "RUNNING")
    assert row is not None and row.status == "RUNNING" and row.version == 1

    row = repo.update_status("job-1", "COMPLETED", scan_id="scan-9")
    assert row is not None and row.status == "COMPLETED" and row.version == 2
    assert row.completed_at is not None

    # unknown job -> None
    assert repo.update_status("missing", "RUNNING") is None


def test_update_status_refuses_to_leave_terminal_state():
    session = _job_session()
    repo = JobRepository(session)
    session.add(ScanJob(id="job-2", job_type="MANUAL", target_repo="r", triggered_by="t", status="COMPLETED", version=3))
    session.commit()

    # a stale worker finishing after the reaper failed the job: refused
    assert repo.update_status("job-2", "COMPLETED", progress={"percent": 100}) is None
    assert repo.update_status("job-2", "RUNNING") is None
    row = session.query(ScanJob).filter(ScanJob.id == "job-2").one()
    assert row.status == "COMPLETED" and row.version == 3

    # administrative force overrides the guard
    forced = repo.update_status("job-2", "FAILED", error_message="admin override", force=True)
    assert forced is not None and forced.status == "FAILED" and forced.version == 4


def test_update_status_detects_version_race():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    maker = sessionmaker(bind=engine, expire_on_commit=False)
    session_a, session_b = maker(), maker()

    session_a.add(ScanJob(id="job-3", job_type="MANUAL", target_repo="r", triggered_by="t", status="RUNNING", version=5))
    session_a.commit()

    repo = JobRepository(session_a)
    # the repository has now seen the row; its identity map holds version 5
    assert repo.get_by_id("job-3").version == 5

    # another process (reaper) wins the race on a separate connection
    session_b.execute(
        ScanJob.__table__.update()
        .where(ScanJob.__table__.c.id == "job-3")
        .values(version=6, status="FAILED", error_message="reaped")
    )
    session_b.commit()

    # the stale writer's compare-and-set matches zero rows: conflict, not a
    # silent overwrite of the reaper's verdict
    assert repo.update_status("job-3", "COMPLETED") is None
    row = session_b.query(ScanJob).filter(ScanJob.id == "job-3").one()
    assert row.status == "FAILED" and row.version == 6


# ---------------------------------------------------------------------------
# Round 27 — cross-rule conflict analysis (audit 65 P0#1)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_policy_rule_conflicts_endpoint_reports_pack_findings():
    app, session = _make_app()
    async with _client(app) as c:
        r = await c.get("/api/v1/policy/rules/conflicts")
        assert r.status_code == 200
        body = r.json()
        assert body["rule_count"] > 0
        assert "pack_hash" in body and body["override_count"] == 0

        # the shipped packs carry two known real findings: CBUAE-001
        # duplicates the baseline deny-list, and BASELINE-005 is subsumed
        # by the forbidden-algorithm rules
        entries = {(item["type"], tuple(item["rules"])) for item in body["conflicts"]}
        assert ("EXACT_DUPLICATE", ("BASELINE-001", "CBUAE-001")) in entries
        assert ("SHADOWED", ("BASELINE-005", "BASELINE-001")) in entries
        counts = {}
        for item in body["conflicts"]:
            counts[item["type"]] = counts.get(item["type"], 0) + 1
        assert body["counts"] == counts

        # an override disabling CBUAE-001 must remove its conflicts
        session.add(PolicyRuleOverride(rule_id="CBUAE-001", enabled=False,
                                       updated_by="admin-1"))
        session.commit()
        r2 = await c.get("/api/v1/policy/rules/conflicts")
        assert r2.status_code == 200
        entries2 = {(item["type"], tuple(item["rules"])) for item in r2.json()["conflicts"]}
        assert ("EXACT_DUPLICATE", ("BASELINE-001", "CBUAE-001")) not in entries2
        assert ("SHADOWED", ("BASELINE-005", "CBUAE-001")) not in entries2
        # the baseline shadow is independent of the UAE pack
        assert ("SHADOWED", ("BASELINE-005", "BASELINE-001")) in entries2


@pytest.mark.asyncio
async def test_policy_rule_coverage_endpoint_reports_matrix():
    app, session = _make_app()
    async with _client(app) as c:
        r = await c.get("/api/v1/policy/rules/coverage")
        assert r.status_code == 200
        body = r.json()
        assert body["rule_count"] >= 60
        assert body["covered_count"] + body["uncovered_count"] == body["rule_count"]
        assert 0.5 < body["coverage_ratio"] <= 1.0

        # every rule carries its pack and coverage state
        row = body["rules"][0]
        assert {"rule_id", "pack", "referenced_by", "covered"} <= set(row)
        covered_row = next(x for x in body["rules"] if x["covered"])
        assert covered_row["referenced_by"]
        assert all(x["pack"] for x in body["rules"])

        # per-pack rollups agree with the row-level data
        for pack, stats in body["by_pack"].items():
            rows = [x for x in body["rules"] if x["pack"] == pack]
            assert stats["rules"] == len(rows)
            assert stats["covered"] == sum(1 for x in rows if x["covered"])

        assert "not a proof of absence" in body["method"]["caveat"]
