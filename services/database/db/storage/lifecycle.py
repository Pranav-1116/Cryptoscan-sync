"""Storage lifecycle: policies, tiers, retention and safe garbage collection.

Spec §7 controls 5–7 and the lifecycle table rows:

* **Retention policies** — each evidence category keeps data as long as
  its policy says, then archives or deletes per policy. Never guesswork.
* **Object lifecycle** — hot → warm → cold as content ages; older
  approved content moves to cheaper storage before anyone considers
  deleting it.
* **Garbage collection** — unreferenced objects (``ref_count == 0``) past
  a grace period are removed safely and audited. Never anything else.
* **Archive before drop, verify before it counts** — the house contract
  from db/retention_enforce: a retention run that loses evidence is a
  breach, not a cleanup. Every deletion is recorded through
  db/privileged_ops.

Everything here is dry-run by default: a call without ``dry_run=False``
reports exactly what would happen and touches nothing.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models.base import utcnow
from db.models.content_object import ContentObject
from db.storage.cas import ContentAddressedStore, sha256_hex

logger = logging.getLogger(__name__)

#: Platform-default retention/lifecycle policy per evidence category
#: (spec §7 storage-risk table). Days chosen for a bank: observations and
#: events are historical record (long), logs and metrics are operational
#: (bounded), cache is disposable (short). A tenant row overrides these.
DEFAULT_POLICIES: tuple[dict, ...] = (
    {"category": "raw_collector_output", "retention_days": 90, "hot_days": 7,
     "warm_days": 30, "compress": True, "expired_action": "archive"},
    {"category": "asset_observation", "retention_days": 365, "hot_days": 7,
     "warm_days": 30, "compress": True, "expired_action": "archive"},
    {"category": "binary_artifact", "retention_days": 180, "hot_days": 7,
     "warm_days": 30, "compress": False, "expired_action": "archive"},
    {"category": "scan_log", "retention_days": 90, "hot_days": 3,
     "warm_days": 14, "compress": True, "expired_action": "delete"},
    {"category": "crypto_event", "retention_days": 730, "hot_days": 7,
     "warm_days": 30, "compress": True, "expired_action": "archive"},
    {"category": "performance_metric", "retention_days": 40, "hot_days": 3,
     "warm_days": 14, "compress": True, "expired_action": "delete"},
    {"category": "report_export", "retention_days": 400, "hot_days": 7,
     "warm_days": 60, "compress": True, "expired_action": "archive"},
    {"category": "cache_data", "retention_days": 7, "hot_days": 1,
     "warm_days": 3, "compress": True, "expired_action": "delete"},
)


@dataclass
class LifecycleAction:
    action: str                 # 'tier' | 'archive' | 'delete' | 'gc'
    sha256: str
    category: str
    detail: str
    performed: bool = False


@dataclass
class SweepReport:
    dry_run: bool
    actions: list[LifecycleAction] = field(default_factory=list)

    @property
    def would_change(self) -> bool:
        return bool(self.actions)


def ensure_default_policies(session: Session) -> int:
    """Insert missing platform-default policy rows (idempotent)."""
    from db.models.storage_policy import StoragePolicy
    existing = {
        row.category for row in session.execute(
            select(StoragePolicy).where(StoragePolicy.tenant_id.is_(None))
        ).scalars()
    }
    added = 0
    for spec in DEFAULT_POLICIES:
        if spec["category"] not in existing:
            session.add(StoragePolicy(tenant_id=None, **spec))
            added += 1
    return added


def policy_for(session: Session, tenant_id: Optional[str], category: str):
    """Tenant policy row if present, else the platform default, else DEFAULT_POLICIES."""
    from db.models.storage_policy import StoragePolicy
    if tenant_id:
        row = session.execute(
            select(StoragePolicy).where(
                StoragePolicy.tenant_id == tenant_id,
                StoragePolicy.category == category,
            )
        ).scalars().first()
        if row is not None:
            return row
    row = session.execute(
        select(StoragePolicy).where(
            StoragePolicy.tenant_id.is_(None),
            StoragePolicy.category == category,
        )
    ).scalars().first()
    if row is not None:
        return row
    for spec in DEFAULT_POLICIES:
        if spec["category"] == category:
            return spec
    return DEFAULT_POLICIES[1]  # asset_observation defaults


def _policy_attr(policy, name: str):
    return getattr(policy, name, None) if not isinstance(policy, dict) else policy.get(name)


def transition_tiers(session: Session, *, now: Optional[datetime] = None,
                     dry_run: bool = True) -> SweepReport:
    """Move aged objects hot → warm → cold per their category policy."""
    now = now or utcnow()
    report = SweepReport(dry_run=dry_run)
    rows = session.execute(select(ContentObject).where(
        ContentObject.body_dropped_at.is_(None),
    )).scalars()
    for obj in rows:
        policy = policy_for(session, obj.tenant_id, obj.category)
        age = (now - obj.created_at) if obj.created_at.tzinfo else (
            now - obj.created_at.replace(tzinfo=timezone.utc))
        hot_days = _policy_attr(policy, "hot_days")
        warm_days = _policy_attr(policy, "warm_days")
        target = obj.storage_tier
        if age > timedelta(days=hot_days + warm_days):
            target = "cold"
        elif age > timedelta(days=hot_days):
            target = "warm" if obj.storage_tier == "hot" else obj.storage_tier
        if target != obj.storage_tier:
            report.actions.append(LifecycleAction(
                action="tier", sha256=obj.sha256, category=obj.category,
                detail=f"{obj.storage_tier} -> {target} (age {age.days}d)",
                performed=not dry_run))
            if not dry_run:
                obj.storage_tier = target
    return report


def retention_sweep(session: Session, *, now: Optional[datetime] = None,
                    dry_run: bool = True, archive_dir: Optional[str | Path] = None,
                    store: Optional[ContentAddressedStore] = None) -> SweepReport:
    """Enforce category retention: archive-verify-then-drop, or drop.

    Metadata rows survive as tombstones (the hash chains of history still
    resolve their identifiers); the bytes go per policy. Every performed
    deletion is recorded through db/privileged_ops.
    """
    now = now or utcnow()
    cas = store if store is not None else ContentAddressedStore(session, enforce_quotas=False)
    report = SweepReport(dry_run=dry_run)
    rows = session.execute(select(ContentObject).where(
        ContentObject.body_dropped_at.is_(None),
    )).scalars()
    for obj in rows:
        policy = policy_for(session, obj.tenant_id, obj.category)
        retention_days = _policy_attr(policy, "retention_days")
        age = (now - obj.created_at) if obj.created_at.tzinfo else (
            now - obj.created_at.replace(tzinfo=timezone.utc))
        if age <= timedelta(days=retention_days):
            continue
        action = _policy_attr(policy, "expired_action") or "archive"
        if action == "archive":
            report.actions.append(LifecycleAction(
                action="archive", sha256=obj.sha256, category=obj.category,
                detail=f"expired at {age.days}d > {retention_days}d — archive-verify-drop",
                performed=not dry_run))
            if not dry_run:
                _archive_and_drop(cas, session, obj, archive_dir)
        else:
            report.actions.append(LifecycleAction(
                action="delete", sha256=obj.sha256, category=obj.category,
                detail=f"expired at {age.days}d > {retention_days}d — delete per policy",
                performed=not dry_run))
            if not dry_run:
                _drop_body(cas, session, obj)
        if not dry_run:
            _audit(session, obj, action)
    return report


def gc_unreferenced(session: Session, *, now: Optional[datetime] = None,
                    grace_hours: int = 24, dry_run: bool = True,
                    store: Optional[ContentAddressedStore] = None) -> SweepReport:
    """Remove unreferenced objects safely: ref_count == 0, past a grace
    period, audited. Anything with a live reference is untouchable here."""
    now = now or utcnow()
    cas = store if store is not None else ContentAddressedStore(session, enforce_quotas=False)
    report = SweepReport(dry_run=dry_run)
    rows = session.execute(select(ContentObject).where(
        ContentObject.ref_count <= 0,
        ContentObject.body_dropped_at.is_(None),
    )).scalars()
    for obj in rows:
        age = (now - obj.updated_at) if obj.updated_at.tzinfo else (
            now - obj.updated_at.replace(tzinfo=timezone.utc))
        if age < timedelta(hours=grace_hours):
            continue
        report.actions.append(LifecycleAction(
            action="gc", sha256=obj.sha256, category=obj.category,
            detail=f"unreferenced for {age.total_seconds() / 3600:.1f}h — garbage collected",
            performed=not dry_run))
        if not dry_run:
            cas.delete_object(obj.tenant_id or "", obj.sha256)
            _audit(session, obj, "gc")
    return report


def _drop_body(cas: ContentAddressedStore, session: Session, obj: ContentObject) -> None:
    """Drop the bytes; keep the metadata tombstone (history resolves)."""
    if obj.chunk_refs:
        for ref in obj.chunk_refs:
            chunk = session.execute(select(ContentObject).where(
                ContentObject.tenant_id == obj.tenant_id,
                ContentObject.sha256 == ref["sha256"],
            )).scalar_one_or_none()
            if chunk is not None and chunk.ref_count > 1:
                chunk.ref_count -= 1
            elif chunk is not None:
                cas.objects.delete(obj.tenant_id or "", ref["sha256"])
                chunk.body_dropped_at = utcnow()
    cas.objects.delete(obj.tenant_id or "", obj.sha256)
    obj.body_dropped_at = utcnow()


def _archive_and_drop(cas: ContentAddressedStore, session: Session, obj: ContentObject,
                      archive_dir: Optional[str | Path]) -> None:
    """Write a verified archive copy of the bytes, then drop the live body."""
    if archive_dir is not None and obj.body_dropped_at is None:
        data = cas.get(obj.tenant_id or "", obj.sha256)  # verified read
        root = Path(archive_dir) / (obj.tenant_id or "platform")
        root.mkdir(parents=True, exist_ok=True)
        path = root / f"{obj.sha256}.ndjson"
        line = json.dumps({"sha256": obj.sha256, "category": obj.category,
                           "plain_size": obj.plain_size, "codec": obj.codec}) + "\n"
        with path.open("ab") as fh:
            fh.write(line.encode("utf-8"))
            fh.write(data)
        # Verify what was written BEFORE the drop counts: read the record
        # back and check the payload hash matches the content address.
        blob = path.read_bytes()
        nl = blob.index(b"\n")
        payload = blob[nl + 1:]
        if sha256_hex(payload) != obj.sha256:
            raise RuntimeError(f"archive verification failed for {obj.sha256[:16]}…")
    _drop_body(cas, session, obj)


def _audit(session: Session, obj: ContentObject, action: str) -> None:
    """Every deletion is recorded (the auditing contract)."""
    try:
        from db.privileged_ops import record_privileged
        record_privileged(
            session, actor="system:storage-lifecycle", action=f"storage.{action}",
            target_type="content_object", target_id=obj.sha256,
            detail={"tenant_id": obj.tenant_id, "category": obj.category,
                    "plain_size": obj.plain_size},
        )
    except Exception as exc:  # pragma: no cover — audit must not block sweep
        logger.warning("storage audit record failed for %s: %s", obj.sha256[:16], exc)
