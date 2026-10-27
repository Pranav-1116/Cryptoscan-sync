"""Task-level migration tracking: progress, forecasting, milestones, sync.

The project's ``progress`` float is *derived* (task-based), never trusted
from the caller — completing tasks recomputes it automatically.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models.migration_project import MigrationMilestone, MigrationProject, MigrationTask

TASK_STATUSES = {"TODO", "IN_PROGRESS", "DONE", "SKIPPED", "BLOCKED"}
_SYNC_STATUSES = {"DONE", "IN_PROGRESS", "TODO", "SKIPPED", "BLOCKED"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime | None) -> datetime | None:
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


class MigrationTaskRepository:
    def __init__(self, session: Session):
        self.session = session

    # ------------------------------------------------------------- tasks

    def add_task(self, project_id: str, **kwargs) -> MigrationTask:
        project = self.session.get(MigrationProject, project_id)
        if project is None:
            raise ValueError("migration project not found")
        status = str(kwargs.get("status") or "TODO").upper()
        if status not in TASK_STATUSES:
            raise ValueError(f"invalid task status '{status}'")
        if status == "BLOCKED" and not (kwargs.get("blocked_reason") or "").strip():
            raise ValueError("a blocked task requires blocked_reason")
        task = MigrationTask(
            project_id=project_id,
            title=str(kwargs.get("title") or "Untitled task")[:300],
            system_id=kwargs.get("system_id"),
            asset_id=kwargs.get("asset_id"),
            evidence_id=kwargs.get("evidence_id"),
            algorithm_from=kwargs.get("algorithm_from"),
            algorithm_to=kwargs.get("algorithm_to"),
            priority=str(kwargs.get("priority") or "P2")[:4],
            effort=kwargs.get("effort"),
            status=status,
            blocked_reason=kwargs.get("blocked_reason"),
            owner=kwargs.get("owner"),
            source=str(kwargs.get("source") or "MANUAL")[:10],
            external_ref=kwargs.get("external_ref"),
            due_date=_aware(kwargs.get("due_date")) if isinstance(kwargs.get("due_date"), datetime) else kwargs.get("due_date"),
            completed_at=_now() if status == "DONE" else kwargs.get("completed_at"),
        )
        self.session.add(task)
        self.session.flush()
        self._refresh_project(project_id)
        return task

    def list_tasks(self, project_id: str) -> list[MigrationTask]:
        return list(
            self.session.execute(
                select(MigrationTask)
                .where(MigrationTask.project_id == project_id)
                .order_by(MigrationTask.priority, MigrationTask.created_at)
            ).scalars()
        )

    def update_task(self, task_id: str, **kwargs) -> Optional[MigrationTask]:
        task = self.session.get(MigrationTask, task_id)
        if task is None:
            return None
        if "status" in kwargs and kwargs["status"] is not None:
            status = str(kwargs["status"]).upper()
            if status not in TASK_STATUSES:
                raise ValueError(f"invalid task status '{status}'")
            reason = kwargs.get("blocked_reason") if status == "BLOCKED" else None
            if status == "BLOCKED" and not (reason or (task.blocked_reason or "").strip()):
                raise ValueError("a blocked task requires blocked_reason")
            task.status = status
            task.completed_at = _now() if status == "DONE" else task.completed_at
            if status != "BLOCKED":
                task.blocked_reason = None
        for key in ("owner", "external_ref", "due_date", "blocked_reason", "title"):
            if key in kwargs and kwargs[key] is not None:
                setattr(task, key, kwargs[key])
        self.session.flush()
        self._refresh_project(task.project_id)
        return task

    def sync_external(self, project_id: str, updates: Iterable[Mapping[str, Any]]) -> dict:
        """Apply status changes originating in an external tracker.

        Honest boundary: without live JIRA/GitHub credentials this is the
        import side of the sync — external systems push
        [{external_ref, status}, ...] and matching tasks update.
        """
        tasks = {
            task.external_ref: task
            for task in self.list_tasks(project_id)
            if task.external_ref
        }
        applied, unknown, invalid = [], [], []
        for update in updates or []:
            ref = str(update.get("external_ref") or "")
            status = str(update.get("status") or "").upper()
            if not ref:
                continue
            task = tasks.get(ref)
            if task is None:
                unknown.append(ref)
                continue
            if status not in _SYNC_STATUSES:
                invalid.append({"external_ref": ref, "status": status})
                continue
            self.update_task(task.id, status=status, blocked_reason=update.get("blocked_reason"))
            applied.append(ref)
        self._refresh_project(project_id)
        return {"applied": len(applied), "applied_refs": applied, "unknown_refs": unknown, "invalid": invalid}

    # ----------------------------------------------------- derived state

    def _task_rows(self, project_id: str) -> list[MigrationTask]:
        return self.list_tasks(project_id)

    def _refresh_project(self, project_id: str) -> None:
        """Recompute the project's progress + status from its tasks."""
        project = self.session.get(MigrationProject, project_id)
        if project is None:
            return
        rows = self._task_rows(project_id)
        actionable = [row for row in rows if row.status != "SKIPPED"]
        done = sum(1 for row in actionable if row.status == "DONE")
        if not rows:
            return  # nothing derived yet; keep the caller's values
        progress = round(100.0 * done / len(actionable), 1) if actionable else 100.0
        project.progress = progress
        if not actionable:
            project.status = "COMPLETED"
        elif progress >= 100.0:
            project.status = "COMPLETED"
        elif any(row.status in {"IN_PROGRESS", "DONE", "BLOCKED"} for row in rows):
            project.status = "IN_PROGRESS"
        self.session.flush()
        self._refresh_milestones(project_id)

    def progress(self, project_id: str) -> dict:
        rows = self._task_rows(project_id)
        actionable = [row for row in rows if row.status != "SKIPPED"]
        done = [row for row in actionable if row.status == "DONE"]
        asset_rows = [row for row in rows if row.asset_id]
        asset_done = [row for row in asset_rows if row.status == "DONE"]
        blocked = [
            {
                "task_id": row.id,
                "title": row.title,
                "reason": row.blocked_reason,
                "owner": row.owner,
                "priority": row.priority,
            }
            for row in rows
            if row.status == "BLOCKED"
        ]
        return {
            "project_id": project_id,
            "tasks_total": len(rows),
            "tasks_actionable": len(actionable),
            "tasks_done": len(done),
            "tasks_blocked": len(blocked),
            "tasks_skipped": sum(1 for row in rows if row.status == "SKIPPED"),
            "task_progress_pct": round(100.0 * len(done) / len(actionable), 1) if actionable else 0.0,
            "asset_based": {
                "assets_total": len({row.asset_id for row in asset_rows}),
                "assets_migrated": len({row.asset_id for row in asset_done}),
                "asset_progress_pct": round(
                    100.0
                    * len({row.asset_id for row in asset_done})
                    / max(1, len({row.asset_id for row in asset_rows})),
                    1,
                ),
            },
            "by_priority": {
                priority: {
                    "total": sum(1 for row in rows if row.priority == priority),
                    "done": sum(1 for row in rows if row.priority == priority and row.status == "DONE"),
                }
                for priority in ("P0", "P1", "P2", "P3")
                if any(row.priority == priority for row in rows)
            },
            "roadblocks": blocked,
        }

    def forecast(self, project_id: str, *, target_date: datetime | None = None) -> dict:
        """Velocity-based completion forecast from completed_at history."""
        rows = self._task_rows(project_id)
        actionable = [row for row in rows if row.status != "SKIPPED"]
        remaining = [row for row in actionable if row.status != "DONE"]
        done_rows = [row for row in actionable if row.status == "DONE" and _aware(row.completed_at)]

        milestone_target = target_date
        if milestone_target is None:
            upcoming = sorted(
                (m for m in self.list_milestones(project_id) if _aware(m.target_date)),
                key=lambda m: _aware(m.target_date),  # type: ignore[arg-type, return-value]
            )
            if upcoming:
                milestone_target = _aware(upcoming[0].target_date)

        now = _now()
        velocity = 0.0
        window_days = 0
        if done_rows:
            first = min(_aware(row.completed_at) for row in done_rows)  # type: ignore[type-var]
            last = max(_aware(row.completed_at) for row in done_rows)  # type: ignore[type-var]
            window_days = max(1.0, (last - first).total_seconds() / 86400 + 1)
            velocity = len(done_rows) / (window_days / 7.0)  # tasks per week

        weeks_remaining = (velocity > 0) and (len(remaining) / velocity) or None
        eta = None
        if weeks_remaining is not None:
            eta = now + timedelta(weeks=weeks_remaining)

        status = "ON_TRACK"
        recommendation = "Continue at the current pace."
        if not done_rows:
            status = "NOT_STARTED"
            recommendation = "No completed tasks yet — start with the P0 items."
        elif not remaining:
            status = "COMPLETED"
            recommendation = "All actionable tasks are done."
        elif milestone_target:
            slack_days = (milestone_target - now).total_seconds() / 86400
            need_velocity = len(remaining) / max(0.1, slack_days / 7.0)
            if eta and eta > milestone_target:  # type: ignore[operator]
                late_days = (eta - milestone_target).days  # type: ignore[operator]
                status = "AT_RISK"
                recommendation = (
                    f"At the current pace the project is ~{late_days} days late. "
                    f"Need {need_velocity:.1f} tasks/week vs current {velocity:.1f}."
                )
        elif eta is None:
            recommendation = "No velocity data and no target date — set a milestone target."

        return {
            "project_id": project_id,
            "tasks_remaining": len(remaining),
            "tasks_done": len(done_rows),
            "velocity_tasks_per_week": round(velocity, 2),
            "weeks_to_completion": round(weeks_remaining, 1) if weeks_remaining is not None else None,
            "eta": eta.isoformat() if eta else None,
            "target_date": milestone_target.isoformat() if milestone_target else None,
            "status": status,
            "recommendation": recommendation,
        }

    # -------------------------------------------------------- milestones

    def add_milestone(self, project_id: str, name: str, target_date: datetime | None = None, notes: str | None = None) -> MigrationMilestone:
        if self.session.get(MigrationProject, project_id) is None:
            raise ValueError("migration project not found")
        row = MigrationMilestone(
            project_id=project_id,
            name=name[:200],
            target_date=_aware(target_date),
            notes=notes,
        )
        self.session.add(row)
        self.session.flush()
        self._refresh_milestones(project_id)
        return row

    def list_milestones(self, project_id: str) -> list[MigrationMilestone]:
        return list(
            self.session.execute(
                select(MigrationMilestone)
                .where(MigrationMilestone.project_id == project_id)
                .order_by(MigrationMilestone.target_date.nulls_last(), MigrationMilestone.created_at)
            ).scalars()
        )

    def _refresh_milestones(self, project_id: str) -> None:
        progress = self.progress(project_id)
        complete = progress["task_progress_pct"] >= 100.0
        at_risk = self.forecast(project_id).get("status") == "AT_RISK"
        now = _now()
        for row in self.list_milestones(project_id):
            target = _aware(row.target_date)
            if complete:
                row.status = "ACHIEVED" if (target is None or now <= target) else "MISSED"
            elif target is not None and now > target:
                row.status = "MISSED"
            elif at_risk:
                row.status = "AT_RISK"
            else:
                row.status = "PLANNED"
        self.session.flush()
