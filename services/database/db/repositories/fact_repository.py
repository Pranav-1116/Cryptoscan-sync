"""Cryptographic fact persistence (advanced/51 P0#1 write-side step, round 35).

Fact rows are DERIVED: `rebuild` recomputes them from the evidence table,
so the fact store is a materialised projection that can be dropped and
rebuilt at any time — a safe migration step toward the 51 rearchitecture,
not a second truth that can drift. Identity comes from
``db.fact_projection.fact_key`` — the exact function the API's live
projection uses, so stored rows and the read contract cannot disagree.

Semantics:

* ``rebuild(file_paths=...)`` recomputes ONLY those files (a scan touched
  them); a full rebuild with no filter is the admin maintenance path.
* Facts whose observations all disappeared (evidence retracted /
  soft-deleted) are honestly marked ``is_current=False`` with counters
  zeroed — deletion history stays queryable, nothing is silently dropped.
* Deterministic ordering and counter recomputation; idempotent (running
  twice changes nothing).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Iterable

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from db.fact_projection import fact_key, identity_values, scanner_id
from db.tenancy import current_tenant, isolation_active
from db.models.cryptographic_fact import CryptographicFact
from db.models.evidence_record import EvidenceRecord

logger = logging.getLogger(__name__)


class FactRepository:
    def __init__(self, session: Session):
        self.session = session

    def rebuild(self, *, file_paths: Iterable[str] | None = None,
                include_deleted: bool = False) -> dict[str, int]:
        """Recompute fact rows from evidence (all files, or the given ones).

        Returns counts: {"facts_upserted", "facts_stale", "evidence_rows"}.
        """
        stmt = select(EvidenceRecord)
        # Scoped admin rebuilds may read platform evidence, but must not
        # rewrite platform facts. The worker (unscoped) rebuilds all tenants.
        scoped_tenant = current_tenant() if isolation_active() else None
        if scoped_tenant is not None:
            stmt = stmt.where(EvidenceRecord.tenant_id == scoped_tenant)
        if not include_deleted:
            stmt = stmt.where(EvidenceRecord.deleted_at.is_(None))
        if file_paths is not None:
            paths = sorted({p for p in file_paths if p})
            if not paths:
                return {"facts_upserted": 0, "facts_stale": 0, "evidence_rows": 0}
            stmt = stmt.where(EvidenceRecord.file_path.in_(paths))
        rows = list(self.session.execute(stmt).scalars())

        grouped: dict[tuple, list[EvidenceRecord]] = {}
        for row in rows:
            grouped.setdefault((row.tenant_id, fact_key(row.to_dict())), []).append(row)

        now = datetime.now(timezone.utc)
        upserted = 0
        for tenant_id, key in sorted(grouped, key=lambda k: (
                str(k[0] or ""), k[1][2], k[1][0], k[1][1], str(k[1][3]), k[1][4])):
            members = grouped[(tenant_id, key)]
            seen = sorted(m.created_at for m in members if m.created_at)
            scanners = sorted({s for s in (scanner_id(m.to_dict()) for m in members) if s})
            evidence_ids = [str(m.id) for m in members]
            values = identity_values(key)
            existing = self._by_identity(tenant_id, key)
            if existing is None:
                existing = CryptographicFact(tenant_id=tenant_id, **values)
                self.session.add(existing)
            existing.observation_count = len(members)
            existing.first_seen = seen[0] if seen else None
            existing.last_seen = seen[-1] if seen else None
            existing.scanners = scanners
            existing.confidences = sorted({
                str(m.confidence) for m in members if m.confidence})
            existing.hardcoded_key_observations = sum(
                1 for m in members if m.is_hardcoded_key)
            existing.evidence_ids = evidence_ids
            existing.rebuilt_at = now
            existing.is_current = True
            upserted += 1

        # Full rebuilds must also retire facts for which no live evidence
        # remains anywhere. A file-scoped rebuild only retires its files.
        stale = 0
        previous_stmt = select(CryptographicFact).where(CryptographicFact.is_current.is_(True))
        if file_paths is not None:
            previous_stmt = previous_stmt.where(CryptographicFact.file_path.in_(paths))
        if scoped_tenant is not None:
            previous_stmt = previous_stmt.where(CryptographicFact.tenant_id == scoped_tenant)
        previous = self.session.execute(previous_stmt).scalars().all()
        live_keys = set(grouped)
        for row in previous:
            if (row.tenant_id, fact_key(row.to_dict())) not in live_keys:
                row.is_current = False
                row.observation_count = 0
                row.first_seen = None
                row.last_seen = None
                row.scanners = []
                row.confidences = []
                row.hardcoded_key_observations = 0
                row.evidence_ids = []
                row.rebuilt_at = now
                stale += 1

        self.session.flush()
        return {"facts_upserted": upserted, "facts_stale": stale,
                "evidence_rows": len(rows)}

    def _by_identity(self, tenant_id: str | None, key: tuple) -> CryptographicFact | None:
        algorithm, purpose, file_path, key_size, mode = key
        return self.session.execute(
            select(CryptographicFact).where(
                CryptographicFact.tenant_id == tenant_id,
                CryptographicFact.algorithm == algorithm,
                func.coalesce(CryptographicFact.purpose, "") == purpose,
                func.coalesce(CryptographicFact.file_path, "") == file_path,
                CryptographicFact.key_size == key_size,
                func.coalesce(CryptographicFact.mode, "") == mode,
            )
        ).scalar_one_or_none()

    def files_for_scan(self, scan_id: str) -> list[str]:
        """The files a scan's evidence touched — the rebuild scope for it."""
        stmt = select(EvidenceRecord.file_path).where(
            EvidenceRecord.scan_id == scan_id,
            EvidenceRecord.deleted_at.is_(None),
        )
        if isolation_active():
            stmt = stmt.where(EvidenceRecord.tenant_id == current_tenant())
        return sorted({path for path in self.session.execute(stmt).scalars() if path})

    def list_current(self, *, algorithm: str | None = None,
                     file_prefix: str | None = None,
                     include_stale: bool = False,
                     limit: int = 1000) -> list[CryptographicFact]:
        stmt = select(CryptographicFact)
        if not include_stale:
            stmt = stmt.where(CryptographicFact.is_current.is_(True))
        if algorithm:
            stmt = stmt.where(CryptographicFact.algorithm == algorithm)
        rows = list(self.session.execute(stmt).scalars())
        if file_prefix:
            rows = [r for r in rows if str(r.file_path or "").startswith(file_prefix)]
        return rows[:limit]

    def latest_activity_by_file(self, files: Iterable[str]) -> dict[tuple[str | None, str], datetime]:
        """Newest evidence activity per tenant and file (including deletions).

        Activity for another tenant's same path must never make this tenant's
        facts appear outdated. Platform evidence also has its own timeline.
        """
        paths = sorted({f for f in files if f})
        if not paths:
            return {}
        latest: dict[tuple[str | None, str], datetime] = {}
        for chunk_start in range(0, len(paths), 500):
            chunk = paths[chunk_start:chunk_start + 500]
            rows = self.session.execute(
                select(
                    EvidenceRecord.tenant_id,
                    EvidenceRecord.file_path,
                    func.max(func.coalesce(EvidenceRecord.deleted_at,
                                           EvidenceRecord.created_at)),
                ).where(EvidenceRecord.file_path.in_(chunk))
                .group_by(EvidenceRecord.tenant_id, EvidenceRecord.file_path)
            ).all()
            for tenant_id, path, stamp in rows:
                if path and stamp is not None:
                    latest[(tenant_id, str(path))] = stamp
        return latest
