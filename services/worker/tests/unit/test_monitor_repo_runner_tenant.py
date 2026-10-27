"""Monitor repo_runner tenant ownership.

The monitor daemon runs unscoped, so a job it created without a tenant landed
in the platform estate (tenant_id NULL — readable by every tenant). The
runner now resolves ownership from trusted state: an explicit
``config["tenant_id"]``, else the RepoConfiguration row that authorized
watching the repo.
"""

from __future__ import annotations

import db.models  # noqa: F401 — register all tables
from db.connection.session import Base
from db.models.repo_configuration import RepoConfiguration
from db.models.scan_job import ScanJob
from worker.monitor import runners


def _session():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)()


def _no_queue_publish(monkeypatch):
    published = []
    # repo_runner imports enqueue_job lazily from the consumer module
    import worker.core.job_consumer as consumer

    monkeypatch.setattr(consumer, "enqueue_job",
                        lambda payload: published.append(payload))
    return published


def test_repo_runner_inherits_tenant_from_repo_configuration(monkeypatch):
    session = _session()
    session.add(RepoConfiguration(repo_url="https://git.example.com/acme/pay.git",
                                  repo_name="pay", enabled=True, tenant_id="tenant-acme"))
    session.commit()
    published = _no_queue_publish(monkeypatch)

    result = runners.repo_runner({"repo": "https://git.example.com/acme/pay.git"}, session)

    assert result["degraded"] is False
    job = session.query(ScanJob).one()
    assert job.tenant_id == "tenant-acme"
    assert published[0]["tenant_id"] == "tenant-acme"
    assert job.job_type == published[0]["job_type"] == "MONITOR_REPOSITORY"


def test_repo_runner_explicit_config_tenant_wins(monkeypatch):
    session = _session()
    session.add(RepoConfiguration(repo_url="https://git.example.com/acme/pay.git",
                                  repo_name="pay", enabled=True, tenant_id="tenant-acme"))
    session.commit()
    published = _no_queue_publish(monkeypatch)

    result = runners.repo_runner(
        {"repo": "https://git.example.com/acme/pay.git", "tenant_id": "tenant-pinned"},
        session,
    )

    assert result["degraded"] is False
    job = session.query(ScanJob).one()
    assert job.tenant_id == "tenant-pinned"
    assert published[0]["tenant_id"] == "tenant-pinned"


def test_repo_runner_without_any_tenant_stays_platform(monkeypatch):
    """No config tenant and no RepoConfiguration row: legacy behaviour
    (platform estate) is preserved — the fix must not invent ownership."""
    session = _session()
    published = _no_queue_publish(monkeypatch)

    result = runners.repo_runner({"repo": "https://git.example.com/unknown/x.git"}, session)

    assert result["degraded"] is False
    job = session.query(ScanJob).one()
    assert job.tenant_id is None
    assert published[0]["tenant_id"] is None
