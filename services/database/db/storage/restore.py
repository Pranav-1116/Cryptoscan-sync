"""Restore testing: verify that stored and archived evidence can be recovered.

Spec §7 control 10: "Restore testing: verify that archived evidence can
actually be recovered." A backup nobody restored is a hope, not a
control. The verification reads content back through the ordinary
content-addressed read path — decrypt, decompress, hash-check — and
records the outcome in ``restore_test_records`` so the control has
evidence of itself. Cold-tier objects get sampled hardest: they are the
ones whose recovery is least exercised.
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models.base import utcnow
from db.models.content_object import ContentObject
from db.models.storage_policy import RestoreTestRecord
from db.storage.cas import ContentAddressedStore


def verify_restorable(session: Session, *, tenant_id: str, object_sha256: str,
                      store: Optional[ContentAddressedStore] = None,
                      record: bool = True) -> RestoreTestRecord:
    """Read one object back through the full path and record the result."""
    cas = store if store is not None else ContentAddressedStore(session, enforce_quotas=False)
    obj = session.execute(select(ContentObject).where(
        ContentObject.tenant_id == tenant_id,
        ContentObject.sha256 == object_sha256,
    )).scalar_one_or_none()
    tier = obj.storage_tier if obj is not None else "unknown"
    ok = False
    bytes_verified = 0
    detail = ""
    try:
        data = cas.get(tenant_id, object_sha256)  # verifies the content hash
        ok = True
        bytes_verified = len(data)
    except Exception as exc:
        detail = str(exc)[:500]
    row = RestoreTestRecord(
        tenant_id=tenant_id, object_sha256=object_sha256,
        restored_from_tier=tier, ok=ok, bytes_verified=bytes_verified,
        tested_at=utcnow(), detail=detail,
    )
    if record:
        session.add(row)
    return row


def run_restore_test(session: Session, *, tenant_id: str, sample: int = 8,
                     store: Optional[ContentAddressedStore] = None) -> list[RestoreTestRecord]:
    """Sample and verify: oldest cold objects first (the least exercised
    recovery path), then the newest hot ones. Returns the test records."""
    cas = store if store is not None else ContentAddressedStore(session, enforce_quotas=False)
    results: list[RestoreTestRecord] = []

    cold = session.execute(
        select(ContentObject).where(
            ContentObject.tenant_id == tenant_id,
            ContentObject.storage_tier == "cold",
            ContentObject.body_dropped_at.is_(None),
        ).order_by(ContentObject.created_at.asc()).limit(sample // 2 or 1)
    ).scalars().all()
    hot = session.execute(
        select(ContentObject).where(
            ContentObject.tenant_id == tenant_id,
            ContentObject.storage_tier != "cold",
            ContentObject.body_dropped_at.is_(None),
        ).order_by(ContentObject.created_at.desc()).limit(sample // 2 or 1)
    ).scalars().all()
    for obj in [*cold, *hot]:
        results.append(verify_restorable(
            session, tenant_id=tenant_id, object_sha256=obj.sha256, store=cas))
    return results
