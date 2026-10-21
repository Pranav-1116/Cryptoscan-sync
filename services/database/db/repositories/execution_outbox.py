"""At-least-once SQL→queue publication, independent of HTTP response delivery."""
from datetime import timedelta
from sqlalchemy import or_, select, update
from db.connection.session import SessionLocal
from db.models.base import utcnow
from db.models.execution_control import ExecutionOutbox
from db.models.scan_job import ScanJob
from db.tenancy import platform_scope


def _descriptor(job):
    return {"job_id": job.id, **{name: getattr(job, name) for name in (
        "tenant_id", "target_repo", "target_branch", "target_commit", "triggered_by", "job_type", "system_id", "progress")}}


def dispatch_one(job_id, publish):
    """Claim, publish, acknowledge. A crash between latter two may duplicate.

    No external transaction is held across publication; SQL QUEUED claim and
    attempt fence make duplicate queue delivery non-executable.
    """
    with platform_scope(), SessionLocal() as session:
        now = utcnow()
        row = session.execute(select(ExecutionOutbox).where(ExecutionOutbox.job_id == job_id)).scalar_one_or_none()
        if row is None or row.state == "PUBLISHED":
            return False
        version, owner = row.version, row.tenant_id
        claimed = session.execute(update(ExecutionOutbox).execution_options(synchronize_session=False).where(
            ExecutionOutbox.id == row.id, ExecutionOutbox.tenant_id == owner,
            ExecutionOutbox.version == version,
            or_((ExecutionOutbox.state == "PENDING") & or_(ExecutionOutbox.lease_until.is_(None), ExecutionOutbox.lease_until <= now), (ExecutionOutbox.state == "PUBLISHING") & (ExecutionOutbox.lease_until <= now)),
        ).values(state="PUBLISHING", version=version + 1, lease_until=now + timedelta(seconds=30)))
        if claimed.rowcount != 1:
            return False
        job = session.execute(select(ScanJob).where(ScanJob.id == job_id, ScanJob.tenant_id == owner)).scalar_one_or_none()
        if job is None or job.status != "QUEUED":
            session.execute(update(ExecutionOutbox).execution_options(synchronize_session=False).where(ExecutionOutbox.id == row.id, ExecutionOutbox.tenant_id == owner).values(state="CANCELLED"))
            session.commit()
            return False
        payload = _descriptor(job)
        row_id = row.id
        session.commit()
    try:
        publish(payload)  # MUST raise on failure; no logging-and-success wrapper.
    except Exception:
        with platform_scope(), SessionLocal() as session:
            session.execute(update(ExecutionOutbox).execution_options(synchronize_session=False).where(ExecutionOutbox.id == row_id, ExecutionOutbox.tenant_id == owner,
                ExecutionOutbox.version == version + 1, ExecutionOutbox.state == "PUBLISHING").values(state="PENDING", version=version + 2, lease_until=None))
            session.commit()
        raise
    with platform_scope(), SessionLocal() as session:
        session.execute(update(ExecutionOutbox).execution_options(synchronize_session=False).where(ExecutionOutbox.id == row_id, ExecutionOutbox.tenant_id == owner,
            ExecutionOutbox.version == version + 1, ExecutionOutbox.state == "PUBLISHING").values(state="PUBLISHED", version=version + 2, published_at=utcnow(), lease_until=None))
        session.commit()
    return True


def dispatch_pending(publish, *, limit=100):
    # Stable oldest-first publication; this is NOT starvation-free worker
    # scheduling or exactly-once delivery. A bounded batch avoids monopolizing
    # maintenance and allows every replica to contend using the same SQL CAS.
    with platform_scope(), SessionLocal() as session:
        now = utcnow()
        ids = list(session.execute(select(ExecutionOutbox.job_id).where(or_(
            (ExecutionOutbox.state == "PENDING") & or_(ExecutionOutbox.lease_until.is_(None), ExecutionOutbox.lease_until <= now),
            (ExecutionOutbox.state == "PUBLISHING") & (ExecutionOutbox.lease_until <= now),
        )).order_by(ExecutionOutbox.created_at, ExecutionOutbox.id).limit(min(max(limit, 1), 1000))).scalars())
    count = 0
    for job_id in ids:
        count += bool(dispatch_one(job_id, publish))
    return count


def defer(job_id, owner):
    """Durably back off a capacity/fairness loser before acknowledging delivery."""
    with SessionLocal() as session:
        job = session.execute(select(ScanJob).where(ScanJob.id == job_id, ScanJob.tenant_id == owner, ScanJob.status == "QUEUED")).scalar_one_or_none()
        if job is None:
            return
        session.execute(update(ExecutionOutbox).execution_options(synchronize_session=False).where(
            ExecutionOutbox.job_id == job_id, ExecutionOutbox.tenant_id == owner,
            ExecutionOutbox.state.in_(["PENDING", "PUBLISHING", "PUBLISHED"])
        ).values(state="PENDING", lease_until=utcnow() + timedelta(seconds=5), version=ExecutionOutbox.version + 1))
        session.commit()
