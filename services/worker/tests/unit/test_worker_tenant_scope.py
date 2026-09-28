"""What tenant a background job runs as.

fix.md item 9 lists "background-worker tenant tests" as its own category, and
it is the one place tenant isolation is easiest to lose: the API resolves a
tenant from the caller's session, but a worker has no caller. It has only
whatever the queue carried.

The monitor path does this correctly -- monitor/network_sweep.py reads
target.tenant_id and wraps the work in tenant_scope(). The scan pipeline does
not, and these tests pin exactly where it stops:

  API enqueue -> Redis JSON -> ScanJob dataclass -> JobExecutor -> PipelineRunner
                                    ^                    ^
                          tenant_id not a field    no scope entered

Outside a scope the ORM guard is inert and stamp_tenant() is a no-op, so rows
the worker writes get tenant_id = NULL. NULL is not "nobody" -- db.tenancy
defines it as the platform estate, which every tenant can read. So a tenant's
scan findings land where all of its neighbours can see them.

These are characterisation tests: they assert the behaviour as it is today,
so the gap is visible in CI rather than in a reviewer's notes. They are
written to FAIL loudly once the propagation is added, with a message saying
so -- that is the intended signal to update them, not a regression.
"""

from __future__ import annotations

import dataclasses
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from db.connection.session import Base
from db.models.scan import Scan
from db.tenancy import current_tenant, install_tenant_guard, platform_scope, tenant_scope
from worker.core.job_consumer import ScanJob

BANK_A = "11111111-1111-1111-1111-111111111111"


@pytest.fixture()
def session():
    install_tenant_guard()
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine, expire_on_commit=False)()
    yield s
    s.close()
    engine.dispose()


def _write_scan(session, target: str) -> Scan:
    """Write the way a pipeline stage does: construct, add, commit."""
    row = Scan(target_location=target, status="COMPLETED",
               scan_start=datetime.now(timezone.utc))
    session.add(row)
    session.commit()
    return row


# --------------------------------------------------------------------------- #
# the gap
# --------------------------------------------------------------------------- #

def test_queue_job_descriptor_does_not_carry_a_tenant():
    """The tenant is lost at the queue boundary, before the worker ever runs.

    db.models.scan_job.ScanJob (the row) is TenantScoped and has tenant_id.
    worker.core.job_consumer.ScanJob (the descriptor that actually travels
    through Redis) does not, so there is nothing for the executor to scope to
    even if it wanted to.
    """
    fields = {f.name for f in dataclasses.fields(ScanJob)}
    assert "tenant_id" not in fields, (
        "ScanJob now carries tenant_id -- the queue boundary has been fixed. "
        "Update this test and make JobExecutor enter tenant_scope(job.tenant_id)."
    )


def test_a_scan_written_outside_a_scope_lands_in_the_platform_estate(session):
    """This is what the worker does today, and why it matters.

    NULL tenant_id is not "unowned": db.tenancy treats it as the platform
    estate and shows it to every tenant. So an unscoped worker write is not a
    missing label, it is a disclosure.
    """
    row = _write_scan(session, "https://git/bank-a/core.git")
    assert row.tenant_id is None

    # A different tenant can read it.
    with tenant_scope("22222222-2222-2222-2222-222222222222"):
        visible = session.query(Scan).filter(Scan.id == row.id).one_or_none()
    assert visible is not None, (
        "platform-estate rows are no longer visible across tenants -- the "
        "NULL-means-shared rule changed; re-read db.tenancy and update this."
    )


def test_job_executor_enters_no_tenant_scope(session):
    """Pin the executor's behaviour at the point the scope should be entered."""
    import inspect

    from worker.core import job_executor

    source = inspect.getsource(job_executor)
    assert "tenant_scope" not in source, (
        "JobExecutor now references tenant_scope -- the worker gap is being "
        "closed. Update these characterisation tests to assert the new "
        "behaviour instead."
    )


# --------------------------------------------------------------------------- #
# the mechanism works; only the propagation is missing
# --------------------------------------------------------------------------- #

def test_the_same_write_is_attributed_correctly_when_a_scope_is_entered(session):
    """Proof the fix is propagation, not new machinery.

    Identical write, wrapped in tenant_scope: stamp_tenant attributes it and
    the row stops being visible to other tenants. Whoever closes this gap
    needs to carry tenant_id through the queue and wrap the executor -- the
    guard already does the rest.
    """
    with tenant_scope(BANK_A):
        row = _write_scan(session, "https://git/bank-a/core.git")
        assert current_tenant() == BANK_A

    with platform_scope():
        stored = session.query(Scan).filter(Scan.id == row.id).one()
    assert stored.tenant_id == BANK_A

    with tenant_scope("22222222-2222-2222-2222-222222222222"):
        assert session.query(Scan).filter(Scan.id == row.id).one_or_none() is None


def test_the_monitor_path_already_does_this(session):
    """network_sweep is the worked example to copy."""
    import inspect

    from worker.monitor import network_sweep

    source = inspect.getsource(network_sweep)
    assert "tenant_scope(" in source, (
        "the monitor path no longer scopes its work; that was the one worker "
        "path doing this correctly"
    )
