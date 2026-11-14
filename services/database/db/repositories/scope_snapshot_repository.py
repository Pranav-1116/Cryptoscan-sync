"""Scope snapshot repository — named revisions of the authorized scope.

Rows are written only by the control-plane route (POST /scope/snapshots);
reads feed the server-side scope diff. The repository stores exactly what
the resolver produced, so a diff never re-derives history the database
does not have.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models.onboarding import ScopeSnapshot


def scope_content_hash(entries: list[dict[str, Any]], envelope: dict[str, Any]) -> str:
    """Deterministic hash over exactly what the snapshot stores.

    Two revisions with the same hash are the same authorization state —
    sorted keys so a serialization difference is not a phantom change.
    """
    canonical = json.dumps({"entries": entries, "envelope": envelope},
                           sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


class ScopeSnapshotRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def create(self, *, org_id: str, entries: list[dict[str, Any]],
               envelope: dict[str, Any], label: str | None = None,
               tenant_id: str | None = None,
               created_by: str | None = None) -> ScopeSnapshot:
        row = ScopeSnapshot(
            org_id=org_id,
            tenant_id=tenant_id,
            label=label,
            content_hash=scope_content_hash(entries, envelope),
            entries=entries,
            envelope=envelope,
            created_by=created_by,
        )
        self.session.add(row)
        self.session.commit()
        self.session.refresh(row)
        return row

    def list(self, *, org_id: str | None = None,
             tenant_id: str | None = None, limit: int = 50) -> list[ScopeSnapshot]:
        stmt = select(ScopeSnapshot).order_by(ScopeSnapshot.created_at.desc())
        if org_id is not None:
            stmt = stmt.where(ScopeSnapshot.org_id == org_id)
        if tenant_id is not None:
            stmt = stmt.where(ScopeSnapshot.tenant_id == tenant_id)
        return list(self.session.execute(stmt.limit(limit)).scalars().all())

    def get(self, snapshot_id: str) -> Optional[ScopeSnapshot]:
        return self.session.execute(
            select(ScopeSnapshot).where(ScopeSnapshot.id == snapshot_id)
        ).scalar_one_or_none()
