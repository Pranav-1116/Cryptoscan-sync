"""Storage quotas: per-tenant and per-job limits (spec §7 control 8).

A continuous collector that silently grows the estate until the disk
fills is the failure mode these prevent. Quotas are checked at write time
by the content-addressed store and reported by monitoring — a run that
would exceed its budget is refused loudly, mid-run, while it can still be
acted on.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from db.models.content_object import ContentObject
from db.models.storage_policy import StorageQuota


class QuotaExceeded(RuntimeError):
    """The write would push the estate past a configured storage quota."""

    def __init__(self, message: str, *, scope: str, limit_bytes: int, used_bytes: int):
        super().__init__(message)
        self.scope = scope
        self.limit_bytes = limit_bytes
        self.used_bytes = used_bytes


@dataclass(frozen=True)
class QuotaUsage:
    bytes_used: int
    object_count: int
    limit_bytes: Optional[int]
    limit_objects: Optional[int]


def _usage_rows(session: Session, tenant_id: str, job_id: Optional[str]):
    """Bytes/objects counted against a quota scope.

    Quotas are accounted in PLAINTEXT bytes — the evidence volume a tenant
    produces. Compression savings show up in monitoring, not as extra
    quota; the budget question is "how much evidence is this estate
    generating", and add_bytes (len(data)) and usage must be the same
    unit or the check is nonsense.
    """
    stmt = select(
        func.coalesce(func.sum(ContentObject.plain_size), 0),
        func.count(ContentObject.id),
    ).where(
        ContentObject.tenant_id == tenant_id,
        ContentObject.body_dropped_at.is_(None),
    )
    return session.execute(stmt).one()


def usage(session: Session, tenant_id: str, job_id: Optional[str] = None) -> QuotaUsage:
    """Effective quota usage: a job-scope quota bounds the job when present,
    otherwise the tenant-scope quota bounds the estate (may be unlimited)."""
    bytes_used, object_count = _usage_rows(session, tenant_id, job_id)
    effective: Optional[StorageQuota] = None
    if job_id is not None:
        effective = session.execute(
            select(StorageQuota).where(
                StorageQuota.tenant_id == tenant_id,
                StorageQuota.scope == "job",
                StorageQuota.job_id == job_id,
            )
        ).scalars().first()
    if effective is None:
        effective = session.execute(
            select(StorageQuota).where(
                StorageQuota.tenant_id == tenant_id,
                StorageQuota.scope == "tenant",
            )
        ).scalars().first()
    return QuotaUsage(
        bytes_used=int(bytes_used),
        object_count=int(object_count),
        limit_bytes=(effective.max_bytes if effective else None),
        limit_objects=((effective.max_objects or None) if effective else None),
    )


def check_quota(session: Session, tenant_id: str, *, add_bytes: int = 0,
                add_objects: int = 1, job_id: Optional[str] = None) -> None:
    """Raise :class:`QuotaExceeded` when the addition would breach a quota."""
    u = usage(session, tenant_id, job_id=job_id)
    if u.limit_bytes is not None and u.bytes_used + add_bytes > u.limit_bytes:
        raise QuotaExceeded(
            f"storage quota exceeded: {u.bytes_used}+{add_bytes} > {u.limit_bytes} bytes",
            scope=("job" if job_id else "tenant"), limit_bytes=u.limit_bytes,
            used_bytes=u.bytes_used,
        )
    if u.limit_objects is not None and u.object_count + add_objects > u.limit_objects:
        raise QuotaExceeded(
            f"storage object quota exceeded: "
            f"{u.object_count}+{add_objects} > {u.limit_objects} objects",
            scope=("job" if job_id else "tenant"), limit_bytes=u.limit_objects,
            used_bytes=u.object_count,
        )
