"""Persistence + roll-ups for CI gate evaluations."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from db.models.gate_evaluation import GateEvaluation


class GateEvaluationRepository:
    def __init__(self, session: Session):
        self.session = session

    def record(
        self,
        *,
        scan_id: str,
        decision: str,
        profile: str = "standard",
        blocking_count: int = 0,
        warning_count: int = 0,
        target_location: str | None = None,
        actor: str | None = None,
    ) -> GateEvaluation:
        row = GateEvaluation(
            scan_id=scan_id,
            decision=decision,
            profile=profile,
            blocking_count=blocking_count,
            warning_count=warning_count,
            target_location=(target_location or "")[:500] or None,
            actor=actor,
            created_at=datetime.now(timezone.utc),
        )
        self.session.add(row)
        self.session.flush()
        return row

    def stats(self, *, days: int = 30) -> dict:
        """Roll-up for the blocked-deployments view: counts + per-repo split."""
        since = datetime.now(timezone.utc) - timedelta(days=max(1, days))
        base = select(GateEvaluation).where(GateEvaluation.created_at >= since)
        rows = list(self.session.execute(base).scalars())
        blocked = [row for row in rows if row.decision == "FAIL"]
        by_repo: dict[str, dict] = {}
        for row in blocked:
            repo = row.target_location or "unknown"
            entry = by_repo.setdefault(repo, {"blocked": 0, "findings": 0})
            entry["blocked"] += 1
            entry["findings"] += int(row.blocking_count or 0)
        return {
            "days": days,
            "evaluations": len(rows),
            "blocked": len(blocked),
            "passed": sum(1 for row in rows if row.decision == "PASS"),
            "warned": sum(1 for row in rows if row.decision == "WARN"),
            "blocking_findings": sum(int(row.blocking_count or 0) for row in rows),
            "by_repo": sorted(
                ({"repo": repo, **counts} for repo, counts in by_repo.items()),
                key=lambda item: (-item["blocked"], item["repo"]),
            )[:10],
            "profiles": dict(
                self.session.execute(
                    select(GateEvaluation.profile, func.count())
                    .where(GateEvaluation.created_at >= since)
                    .group_by(GateEvaluation.profile)
                ).all()
            ),
        }
