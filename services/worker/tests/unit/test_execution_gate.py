"""Execution-time re-validation for dequeued jobs (§4.1, round 46).

Admission at enqueue is not admission at execution: an emergency stop
engaged after the job was queued, a tightened safe-scan policy, or source
roots that no longer contain the target must refuse the job at the worker —
the last point before a collector runs. A refused job is stamped FAILED
with the reason and NO collector is invoked.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import db.models  # noqa: F401 — register tables
from db.connection.session import Base
from db.models.scan_job import ScanJob as ScanJobRow
from worker.core.execution_gate import (
    GateUnavailable,
    gate_job,
    policy_decision,
    target_decision,
)
from worker.core.job_consumer import ScanJob


def _job(target_repo: str = "/workspace/repo") -> ScanJob:
    return ScanJob(job_id="job-1", target_repo=target_repo, target_branch="main", triggered_by="alice")


# ── policy decision ───────────────────────────────────────────────────


def test_policy_permits_when_no_emergency_stop(monkeypatch):
    import worker.core.execution_gate as gate

    monkeypatch.setattr(gate, "_matching_policy", lambda: {"mode": "standard"})
    permitted, reason = policy_decision()
    assert permitted and reason is None


def test_engaged_emergency_stop_refuses_execution(monkeypatch):
    import worker.core.execution_gate as gate

    monkeypatch.setattr(gate, "_matching_policy", lambda: {"emergency_stop": True})
    permitted, reason = policy_decision()
    assert not permitted
    assert "emergency stop" in reason


def test_control_plane_outage_fails_closed(monkeypatch):
    import worker.core.execution_gate as gate

    def _boom():
        raise GateUnavailable("database unreachable")

    monkeypatch.setattr(gate, "_matching_policy", _boom)
    permitted, reason = policy_decision()
    assert not permitted
    assert "fail-closed" in reason


def test_excluded_asset_is_refused(monkeypatch):
    import worker.core.execution_gate as gate

    monkeypatch.setattr(gate, "_matching_policy", lambda: {"mode": "standard", "excluded_assets": ["/workspace/repo"]})
    permitted, reason = gate_job(_job("/workspace/repo"), repository_target=True)
    assert not permitted
    assert "excluded" in reason


# ── target decision ───────────────────────────────────────────────────


def test_repository_target_inside_source_roots_is_permitted(tmp_path, monkeypatch):
    monkeypatch.setenv("CRYPTOSCAN_SOURCE_ROOTS", str(tmp_path))
    repo = tmp_path / "repo"
    repo.mkdir()
    permitted, reason = target_decision(str(repo))
    assert permitted and reason is None


def test_repository_target_outside_source_roots_is_refused(monkeypatch):
    monkeypatch.setenv("CRYPTOSCAN_SOURCE_ROOTS", "/workspace/declared")
    permitted, reason = target_decision("/etc")
    assert not permitted
    assert "outside the allowed source roots" in reason


def test_gate_skips_containment_for_non_repository_jobs(monkeypatch):
    import worker.core.execution_gate as gate

    monkeypatch.setattr(gate, "_matching_policy", lambda: {"mode": "standard"})
    # a binary target string is not a filesystem path — policy still applies,
    # containment does not
    permitted, reason = gate_job(_job("binary://artifact-42"), repository_target=False)
    assert permitted and reason is None


# ── executor integration: refused means FAILED row + no collector ────


@pytest.fixture()
def db_env(monkeypatch):
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    import db.connection.session as connection

    monkeypatch.setattr(connection, "SessionLocal", factory)
    session = factory()
    from db.models.user import User

    session.add(User(id="actor-alice", username="alice", password_hash="unused", roles="admin", is_active=True))
    session.add(
        ScanJobRow(
            id="job-1",
            job_type="MANUAL",
            target_repo="/workspace/repo",
            target_branch="main",
            triggered_by="alice",
            status="QUEUED",
            progress={"execution_authority": {"v": 1, "kind": "user", "id": "actor-alice"}},
        )
    )
    session.commit()
    yield session, factory
    session.close()
    engine.dispose()


def test_refused_job_is_stamped_failed_and_never_runs(db_env, monkeypatch):
    import worker.core.execution_gate as gate
    from worker.core.job_executor import JobExecutor

    session, _factory = db_env
    monkeypatch.setattr(gate, "_matching_policy", lambda: {"emergency_stop": True})
    # the pipeline must NEVER be reached
    monkeypatch.setattr(JobExecutor, "__init__", lambda self, **kw: setattr(self, "runner", _NeverRunner()))

    class _NeverRunner:
        def run(self, **kwargs):  # pragma: no cover — the assertion is that this never runs
            raise AssertionError("pipeline ran despite an engaged emergency stop")

    executor = JobExecutor()
    result = executor.execute(_job("/workspace/repo"))
    assert result is False
    row = session.query(ScanJobRow).filter_by(id="job-1").one()
    assert row.status == "FAILED"
    assert "execution gate" in row.error_message
    assert "emergency stop" in row.error_message


def test_permitted_job_proceeds_to_the_pipeline(db_env, monkeypatch, tmp_path):
    import worker.core.execution_gate as gate
    from worker.core.job_executor import JobExecutor

    session, _factory = db_env
    monkeypatch.setenv("CRYPTOSCAN_SOURCE_ROOTS", str(tmp_path))
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    session.query(ScanJobRow).filter_by(id="job-1").update({"target_repo": str(repo_dir)})
    session.commit()
    monkeypatch.setattr(gate, "_matching_policy", lambda: {"mode": "standard"})

    class _StubRunner:
        def run(self, **kwargs):
            return "scan-123"

    monkeypatch.setattr(JobExecutor, "__init__", lambda self, **kw: setattr(self, "runner", _StubRunner()))
    executor = JobExecutor()
    result = executor.execute(_job(str(repo_dir)))
    assert result is True
    row = session.query(ScanJobRow).filter_by(id="job-1").one()
    session.expire_all()
    assert row.status == "RUNNING", "permitted execution claims the queued row before dispatch"
