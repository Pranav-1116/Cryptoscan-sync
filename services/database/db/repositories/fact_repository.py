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
            grouped.setdefault(fact_key(row.to_dict()), []).append(row)

        now = datetime.now(timezone.utc)
        upserted = 0
        for key in sorted(grouped, key=lambda k: (k[2] or "", k[0], k[1], str(k[3]), k[4])):
            members = grouped[key]
            seen = sorted(m.created_at for m in members if m.created_at)
            scanners = sorted({s for s in (scanner_id(m.to_dict()) for m in members) if s})
            evidence_ids = [str(m.id) for m in members]
            values = identity_values(key)
            existing = self._by_identity(key)
            if existing is None:
                existing = CryptographicFact(**values)
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

        # facts for these files whose evidence vanished entirely
        stale = 0
        touched_paths = None if file_paths is None else sorted(
            {p for p in file_paths if p})
        if touched_paths:
            previous = self.session.execute(
                select(CryptographicFact).where(
                    CryptographicFact.is_current.is_(True),
                    CryptographicFact.file_path.in_(touched_paths),
                )
            ).scalars().all()
            live_keys = set(grouped)
            for row in previous:
                key = (row.algorithm, row.purpose, row.file_path,
                       row.key_size, row.mode)
                if key not in live_keys:
                    row.is_current = False
                    row.observation_count = 0
                    row.evidence_ids = []
                    row.rebuilt_at = now
                    stale += 1

        self.session.flush()
        return {"facts_upserted": upserted, "facts_stale": stale,
                "evidence_rows": len(rows)}

    def _by_identity(self, key: tuple) -> CryptographicFact | None:
        algorithm, purpose, file_path, key_size, mode = key
        return self.session.execute(
            select(CryptographicFact).where(
                CryptographicFact.algorithm == algorithm,
                CryptographicFact.purpose == purpose,
                CryptographicFact.file_path == file_path,
                CryptographicFact.key_size == key_size,
                CryptographicFact.mode == mode,
            )
        ).scalar_one_or_none()

    def files_for_scan(self, scan_id: str) -> list[str]:
        """The files a scan's evidence touched — the rebuild scope for it."""
        return sorted({
            path for path in self.session.execute(
                select(EvidenceRecord.file_path).where(
                    EvidenceRecord.scan_id == scan_id,
                    EvidenceRecord.deleted_at.is_(None),
                )
            ).scalars() if path
        })

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

    def latest_activity_by_file(self, files: Iterable[str]) -> dict[str, datetime]:
        """Per file: the newest evidence activity (created OR soft-deleted).

        A fact row is fresh iff its ``rebuilt_at`` covers this timestamp —
        deletion after a rebuild also makes the row stale, because a
        rebuild would now compute different numbers for that file.
        """
        paths = sorted({f for f in files if f})
        if not paths:
            return {}
        latest: dict[str, datetime] = {}
        for chunk_start in range(0, len(paths), 500):
            chunk = paths[chunk_start:chunk_start + 500]
            rows = self.session.execute(
                select(
                    EvidenceRecord.file_path,
                    func.max(func.coalesce(EvidenceRecord.deleted_at,
                                           EvidenceRecord.created_at)),
                ).where(EvidenceRecord.file_path.in_(chunk))
                .group_by(EvidenceRecord.file_path)
            ).all()
            for path, stamp in rows:
                if path and stamp is not None:
                    latest[str(path)] = stamp
        return latest
