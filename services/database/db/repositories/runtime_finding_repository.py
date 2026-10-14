"""CRUD + aggregation for runtime crypto findings."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from db.models.base import utcnow
from db.models.runtime_finding import RuntimeFinding


def dedup_key_for(row: dict[str, Any]) -> str:
    extra = row.get("extra") or {}
    return "|".join(
        str(part or "")
        for part in (
            row.get("scanner_id"),
            row.get("hostname"),
            row.get("process_name"),
            row.get("pid"),
            row.get("tls_version"),
            row.get("cipher_suite"),
            # bare crypto calls carry no suite: without the algorithm the key,
            # two different ciphers from one process would fold into one row
            row.get("algorithm"),
            extra.get("mode"),
            extra.get("library"),
            extra.get("library_version"),
        )
    )[:400]


class RuntimeFindingRepository:
    def __init__(self, session: Session):
        self.session = session

    def upsert_many(self, rows: list[dict[str, Any]]) -> dict[str, int]:
        """Insert new observations; repeated observations increment counts."""
        created = updated = 0
        now = utcnow()
        for row in rows:
            key = row.get("dedup_key") or dedup_key_for(row)
            existing = self.session.execute(
                select(RuntimeFinding).where(RuntimeFinding.dedup_key == key).limit(1)
            ).scalar_one_or_none()
            if existing is None:
                self.session.add(RuntimeFinding(dedup_key=key, last_seen_at=now, **_columns(row)))
                created += 1
            else:
                existing.observation_count = existing.observation_count + int(row.get("observation_count") or 1)
                existing.last_seen_at = now
                if row.get("extra"):
                    extra = dict(existing.extra or {})
                    extra.update(row["extra"])
                    existing.extra = extra
                updated += 1
        self.session.flush()
        return {"created": created, "updated": updated}

    def list_recent(self, *, limit: int = 100, kind: str | None = None, weak_only: bool = False) -> list[RuntimeFinding]:
        stmt = select(RuntimeFinding).order_by(RuntimeFinding.last_seen_at.desc()).limit(max(1, min(limit, 500)))
        if kind:
            stmt = stmt.where(RuntimeFinding.kind == kind)
        if weak_only:
            stmt = stmt.where((RuntimeFinding.weak_tls.is_(True)) | (RuntimeFinding.status.in_(["DISALLOWED", "DEPRECATED"])))
        return list(self.session.execute(stmt).scalars())

    def search(self, query: str, *, limit: int = 100) -> tuple[list[RuntimeFinding], int]:
        """§5 (round 65): server-side search across the WHOLE runtime-findings
        store — the term is matched in the database over the observable text
        fields (hostname, process, algorithm, cipher suite, TLS version,
        scanner, kind, status), not a client-side filter of the most-recent
        window. Returns the matching page plus the total match count."""
        needle = f"%{query}%"
        condition = or_(
            RuntimeFinding.hostname.ilike(needle),
            RuntimeFinding.process_name.ilike(needle),
            RuntimeFinding.algorithm.ilike(needle),
            RuntimeFinding.cipher_suite.ilike(needle),
            RuntimeFinding.tls_version.ilike(needle),
            RuntimeFinding.scanner_id.ilike(needle),
            RuntimeFinding.kind.ilike(needle),
            RuntimeFinding.status.ilike(needle),
        )
        total = int(self.session.execute(
            select(func.count(RuntimeFinding.id)).where(condition)).scalar() or 0)
        rows = list(self.session.execute(
            select(RuntimeFinding).where(condition)
            .order_by(RuntimeFinding.last_seen_at.desc())
            .limit(max(1, min(limit, 500)))).scalars())
        return rows, total

    def summary(self) -> dict[str, Any]:
        total = self.session.execute(select(func.count(RuntimeFinding.id))).scalar() or 0
        weak = self.session.execute(
            select(func.count(RuntimeFinding.id)).where(
                (RuntimeFinding.weak_tls.is_(True)) | (RuntimeFinding.status.in_(["DISALLOWED", "DEPRECATED"]))
            )
        ).scalar() or 0
        hosts = self.session.execute(select(func.count(func.distinct(RuntimeFinding.hostname)))).scalar() or 0
        day_ago = utcnow() - timedelta(hours=24)
        recent = self.session.execute(
            select(func.count(RuntimeFinding.id)).where(RuntimeFinding.last_seen_at >= day_ago)
        ).scalar() or 0
        top_suites = self.session.execute(
            select(RuntimeFinding.cipher_suite, func.sum(RuntimeFinding.observation_count))
            .where(RuntimeFinding.cipher_suite.isnot(None))
            .group_by(RuntimeFinding.cipher_suite)
            .order_by(func.sum(RuntimeFinding.observation_count).desc())
            .limit(8)
        ).all()
        top_algorithms = self.session.execute(
            select(RuntimeFinding.algorithm, func.sum(RuntimeFinding.observation_count))
            .where(RuntimeFinding.algorithm.isnot(None))
            .group_by(RuntimeFinding.algorithm)
            .order_by(func.sum(RuntimeFinding.observation_count).desc())
            .limit(8)
        ).all()
        return {
            "total_findings": total,
            "weak_findings": weak,
            "hosts": hosts,
            "observations_last_24h": recent,
            "top_cipher_suites": [{"cipher_suite": s, "observations": int(c or 0)} for s, c in top_suites],
            "top_algorithms": [{"algorithm": a, "observations": int(c or 0)} for a, c in top_algorithms],
        }


def _columns(row: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "scanner_id", "kind", "hostname", "process_name", "pid", "tls_version",
        "cipher_suite", "algorithm", "key_size", "status", "quantum_impact",
        "weak_tls", "observation_count", "extra",
    }
    out = {k: v for k, v in row.items() if k in allowed}
    out.setdefault("observation_count", 1)
    return out
