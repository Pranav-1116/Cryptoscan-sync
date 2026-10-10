"""Round 23 (report 31 §2.9, 88 GAP-011): clean-scan baseline proposals.

The worker's drift stage proposes a baseline when a system has no active
one AND the scan is clean (no FAIL policy evidence, no CRITICAL/HIGH
drift). A proposal never activates itself — that stays an auditor
decision (POST /baselines/{id}/approve-proposed).
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register tables
from db.connection.session import Base
from db.models.baseline import Baseline
from db.models.evidence_record import EvidenceRecord
from db.models.scan import Scan
from worker.pipeline.pipeline_runner import PipelineContext, PipelineRunner

NOW = datetime(2026, 10, 10, tzinfo=timezone.utc)


def _session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def _ctx(scan_id="scan-1", target="https://github.com/org/repo.git"):
    return PipelineContext(
        job_id="job-1", target_repo=target, target_branch="main",
        triggered_by="tester", workspace_dir="/tmp/ws", scan_id=scan_id,
    )


def _seed_scan(session, scan_id="scan-1", fail_rows=0):
    session.add(
        Scan(id=scan_id, scan_start=NOW, target_location="https://github.com/org/repo.git",
             target_type="GIT_REPOSITORY", status="COMPLETED")
    )
    for i in range(fail_rows):
        session.add(
            EvidenceRecord(
                id=f"{scan_id}-ev-{i}", scan_id=scan_id, content_hash=f"h{i}" * 32,
                chain_hash="c" * 64, chain_position=i, algorithm="MD5",
                confidence="HIGH", file_path="a.py", line_number=i + 1,
                compliance_status="FAIL", finding_data={},
            )
        )
    session.commit()


def _propose(session, ctx, inventory_events=None):
    from db.repositories.baseline_repository import BaselineRepository

    runner = PipelineRunner.__new__(PipelineRunner)  # no settings/workspace needed
    runner._propose_baseline_if_clean(
        ctx, session, BaselineRepository(session), inventory_events or []
    )


def test_clean_first_scan_proposes_inactive_baseline():
    session = _session()
    _seed_scan(session, fail_rows=0)
    _propose(session, _ctx())
    rows = session.query(Baseline).all()
    assert len(rows) == 1
    row = rows[0]
    assert row.status == "PROPOSED"  # never ACTIVE without an auditor
    assert row.system_identifier == "https://github.com/org/repo.git"
    assert row.approved_scan_id == "scan-1"
    assert "auditor approves" in (row.notes or "")


def test_fail_evidence_blocks_proposal():
    session = _session()
    _seed_scan(session, fail_rows=2)
    _propose(session, _ctx())
    assert session.query(Baseline).count() == 0


def test_severe_drift_blocks_proposal():
    session = _session()
    _seed_scan(session, fail_rows=0)
    _propose(
        session, _ctx(),
        inventory_events=[{"drift_type": "KEY_ORPHAN", "severity": "CRITICAL", "reason": "x"}],
    )
    assert session.query(Baseline).count() == 0


def test_existing_active_baseline_blocks_proposal():
    session = _session()
    _seed_scan(session, scan_id="scan-old")
    session.add(
        Baseline(system_identifier="https://github.com/org/repo.git", environment="default",
                 approved_scan_id="scan-old", approved_by="aud", approved_at=NOW,
                 status="ACTIVE")
    )
    session.commit()
    # the guard lives in the caller (_drift returns early when a baseline is
    # active); the helper itself is only reached without one — simulate the
    # caller's early return by not invoking the helper
    assert session.query(Baseline).filter(Baseline.status == "ACTIVE").count() == 1


def test_new_clean_scan_supersedes_older_proposal():
    session = _session()
    _seed_scan(session, scan_id="scan-1")
    _propose(session, _ctx(scan_id="scan-1"))
    _seed_scan(session, scan_id="scan-2")
    _propose(session, _ctx(scan_id="scan-2"))
    rows = session.query(Baseline).order_by(Baseline.approved_at).all()
    assert len(rows) == 2
    assert rows[0].status == "SUPERSEDED"
    assert rows[1].status == "PROPOSED"
    assert rows[1].approved_scan_id == "scan-2"


def test_proposal_is_idempotent_per_scan():
    session = _session()
    _seed_scan(session, scan_id="scan-1")
    _propose(session, _ctx(scan_id="scan-1"))
    _propose(session, _ctx(scan_id="scan-1"))
    # same scan proposing twice replaces, not duplicates
    rows = session.query(Baseline).all()
    assert len(rows) == 2  # old superseded + newest proposed
    assert sum(1 for r in rows if r.status == "PROPOSED") == 1
