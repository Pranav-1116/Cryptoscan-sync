"""Reconcile untrusted queue hints with persisted ownership before dispatch.

No collector, scope selection or refusal write is authorized by a queue payload.
SQL is the authority. A claim prevents concurrent dequeues of the same QUEUED
row; this is not exactly-once execution or a mid-collector revocation mechanism.
"""

from copy import deepcopy
from dataclasses import replace

from sqlalchemy import select, update

from db.models.scan_job import ScanJob as JobRow
from db.tenancy import platform_scope
from db.repositories.execution_control import BudgetBusy


class QueueRefused(Exception):
    pass


class QueueDeferred(QueueRefused):
    pass


FIELDS = ("tenant_id", "target_repo", "target_branch", "target_commit", "triggered_by", "job_type", "system_id")


def _row(session, job):
    row = session.execute(select(JobRow).where(JobRow.id == job.job_id)).scalar_one_or_none()
    if row is None or any(getattr(row, key) != getattr(job, key) for key in FIELDS):
        raise QueueRefused("Queue descriptor does not match persisted job")
    if row.status != "QUEUED":
        raise QueueRefused("Job is no longer queued")
    stored_options = (row.progress or {}).get("scan_options") or {}
    if stored_options != job.scan_options:
        raise QueueRefused("Queue options do not match persisted job")
    return row


def reconcile(job):
    from db.connection.session import SessionLocal

    try:
        with platform_scope(), SessionLocal() as session:
            row = _row(session, job)
            return replace(job, **{key: getattr(row, key) for key in FIELDS}, progress=deepcopy(row.progress))
    except QueueRefused:
        raise
    except Exception as exc:
        raise QueueRefused("Persisted queue authority unavailable") from exc


def claim(job):
    """Fresh identity/configuration check and compare-and-set before collection."""
    from db.connection.session import SessionLocal
    from db.models.base import utcnow
    from db.repositories.queued_authority import current_authority
    from api.security.rbac import normalize_roles, PERMISSION_MATRIX

    try:
        with platform_scope(), SessionLocal() as session:
            row = _row(session, job)
            authority, roles = current_authority(session, row)
            pinned = (row.progress or {}).get("execution_authority")
            if pinned is None:
                raise QueueRefused("Legacy job lacks pinned enqueue authority; resubmit through admission")
            if pinned != authority:
                raise QueueRefused("Initiating authority changed since enqueue")
            if authority is None:
                raise QueueRefused("Initiating authority is absent or inactive")
            if (
                authority["kind"] != "repository"
                and not set(normalize_roles(roles)) & PERMISSION_MATRIX["scan.trigger"]
            ):
                raise QueueRefused("Initiating authority no longer permits scan execution")
            from db.repositories.execution_control import claim_attempt, required, ExecutionDenied
            if (row.progress or {}).get("execution_control") or required():
                from worker.core.controlled_source import preflight
                preflight()
                from worker.core.static_scan_isolation import _configuration
                if _configuration().ENVIRONMENT.strip().lower() in {"prod", "production"} and session.bind.dialect.name != "postgresql":
                    raise ExecutionDenied("Controlled production execution requires PostgreSQL")
            attempt = claim_attempt(session, row)
            result = session.execute(
                update(JobRow)
                .where(
                    JobRow.id == row.id,
                    JobRow.tenant_id == row.tenant_id,
                    JobRow.version == row.version,
                    JobRow.status == "QUEUED",
                )
                .values(status="RUNNING", version=row.version + 1, started_at=utcnow())
            )
            if result.rowcount != 1:
                raise QueueRefused("Job claim lost a concurrent transition")
            session.commit()
            return attempt
    except BudgetBusy as exc:
        raise QueueDeferred(str(exc)) from exc
    except QueueRefused:
        raise
    except Exception as exc:
        raise QueueRefused("Execution authority or claim unavailable") from exc
