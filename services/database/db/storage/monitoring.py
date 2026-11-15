"""Storage monitoring: usage truth and near-full alerts (spec §7 controls 9).

"Storage monitoring: alert before disks become full." The report answers
the questions a capacity review actually asks — how much is stored, how
much compression saved, what sits in which tier, what is unreferenced and
how old — and the alerts fire on thresholds BEFORE the failure, not after.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from db.models.content_object import ContentObject
from db.storage.quotas import usage


@dataclass
class StorageAlert:
    level: str          # 'warning' | 'critical'
    kind: str           # 'quota_near_full' | 'capacity_near_full' | 'unreferenced_backlog'
    subject: str        # tenant id or 'estate'
    detail: str


@dataclass
class UsageReport:
    tenant_id: Optional[str]
    object_count: int = 0
    plain_bytes: int = 0
    stored_bytes: int = 0
    dropped_objects: int = 0
    by_tier: dict = field(default_factory=dict)
    by_category: dict = field(default_factory=dict)
    unreferenced_count: int = 0
    unreferenced_bytes: int = 0

    @property
    def compression_saved_bytes(self) -> int:
        return max(0, self.plain_bytes - self.stored_bytes)

    def to_dict(self) -> dict:
        return {
            "tenant_id": self.tenant_id,
            "object_count": self.object_count,
            "plain_bytes": self.plain_bytes,
            "stored_bytes": self.stored_bytes,
            "compression_saved_bytes": self.compression_saved_bytes,
            "dropped_objects": self.dropped_objects,
            "by_tier": self.by_tier,
            "by_category": self.by_category,
            "unreferenced_count": self.unreferenced_count,
            "unreferenced_bytes": self.unreferenced_bytes,
        }


def usage_report(session: Session, tenant_id: Optional[str] = None) -> UsageReport:
    """The storage truth for one tenant (or the whole estate when None)."""
    report = UsageReport(tenant_id=tenant_id)
    stmt = select(ContentObject)
    if tenant_id is not None:
        stmt = stmt.where(ContentObject.tenant_id == tenant_id)
    for obj in session.execute(stmt).scalars():
        if obj.body_dropped_at is not None:
            report.dropped_objects += 1
            continue
        report.object_count += 1
        report.plain_bytes += obj.plain_size
        report.stored_bytes += obj.stored_size
        tier = report.by_tier.setdefault(obj.storage_tier, {"objects": 0, "stored_bytes": 0})
        tier["objects"] += 1
        tier["stored_bytes"] += obj.stored_size
        cat = report.by_category.setdefault(obj.category, {"objects": 0, "stored_bytes": 0})
        cat["objects"] += 1
        cat["stored_bytes"] += obj.stored_size
        if obj.ref_count <= 0:
            report.unreferenced_count += 1
            report.unreferenced_bytes += obj.stored_size
    return report


def space_alerts(session: Session, *, tenant_id: Optional[str] = None,
                 capacity_bytes: Optional[int] = None,
                 warn_pct: float = 0.80, critical_pct: float = 0.95) -> list[StorageAlert]:
    """Alerts that fire BEFORE the disk fills — thresholds over quota and
    (when configured) total capacity, plus unreferenced-object backlog."""
    alerts: list[StorageAlert] = []
    tenants: list[Optional[str]] = [tenant_id]
    if tenant_id is None:
        rows = session.execute(
            select(ContentObject.tenant_id).distinct()
        ).scalars().all()
        tenants = list(rows)

    for tid in tenants:
        u = usage(session, tid or "")
        subject = tid or "estate"
        if u.limit_bytes is not None and u.limit_bytes > 0:
            frac = u.bytes_used / u.limit_bytes
            if frac >= critical_pct:
                alerts.append(StorageAlert(
                    "critical", "quota_near_full", subject,
                    f"{u.bytes_used}/{u.limit_bytes} bytes ({frac:.0%} of storage quota)"))
            elif frac >= warn_pct:
                alerts.append(StorageAlert(
                    "warning", "quota_near_full", subject,
                    f"{u.bytes_used}/{u.limit_bytes} bytes ({frac:.0%} of storage quota)"))
        report = usage_report(session, tid)
        if capacity_bytes is not None and capacity_bytes > 0:
            frac = report.stored_bytes / capacity_bytes
            if frac >= critical_pct:
                alerts.append(StorageAlert(
                    "critical", "capacity_near_full", subject,
                    f"{report.stored_bytes}/{capacity_bytes} bytes ({frac:.0%} of capacity)"))
            elif frac >= warn_pct:
                alerts.append(StorageAlert(
                    "warning", "capacity_near_full", subject,
                    f"{report.stored_bytes}/{capacity_bytes} bytes ({frac:.0%} of capacity)"))
        if report.unreferenced_count > 0 and report.unreferenced_bytes > 10 * 1024 * 1024:
            alerts.append(StorageAlert(
                "warning", "unreferenced_backlog", subject,
                f"{report.unreferenced_count} unreferenced objects "
                f"({report.unreferenced_bytes} bytes) await garbage collection"))
    return alerts
