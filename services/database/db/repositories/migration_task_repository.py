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


class _DependencyGateError(ValueError):
    """Start gate refusal — carries the blocking chain for the API layer."""

    def __init__(self, message: str, *, blockers: list) -> None:
        super().__init__(message)
        self.blockers = blockers


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
        project = self.session.execute(select(MigrationProject).where(MigrationProject.id == project_id)).scalars().first()
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
        task = self.session.execute(select(MigrationTask).where(MigrationTask.id == task_id)).scalars().first()
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
        if "depends_on" in kwargs and kwargs["depends_on"] is not None:
            deps = [str(ref) for ref in kwargs["depends_on"] if str(ref).strip()] \
                if isinstance(kwargs["depends_on"], (list, tuple)) else None
            if deps is None:
                raise ValueError("depends_on must be a list of task ids")
            if task.id in deps:
                raise ValueError("a task cannot depend on itself")
            known = {row.id for row in self.list_tasks(task.project_id)}
            unknown = [ref for ref in deps if ref not in known]
            if unknown:
                raise ValueError(f"unknown dependency task ids: {', '.join(unknown)}")
            task.depends_on = sorted(set(deps))
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

    # ------------------------------------------- execution engine (R30)

    def _engine_index(self, project_id: str) -> dict:
        from db import migration_execution as _engine

        return _engine.index_tasks([row.to_dict() for row in self.list_tasks(project_id)])

    def link_dependency(self, task_id: str, depends_on_task_id: str) -> MigrationTask:
        """Add one dependency edge, rejecting cycles before persisting."""
        task = self.session.execute(select(MigrationTask).where(MigrationTask.id == task_id)).scalars().first()
        if task is None:
            raise ValueError("migration task not found")
        dep = self.session.execute(
            select(MigrationTask).where(MigrationTask.id == depends_on_task_id)
        ).scalars().first()
        if dep is None:
            raise ValueError(f"dependency task not found: {depends_on_task_id}")
        if dep.project_id != task.project_id:
            raise ValueError("dependencies must stay inside one project")
        if depends_on_task_id == task_id:
            raise ValueError("a task cannot depend on itself")
        current = list(task.depends_on or [])
        if depends_on_task_id in current:
            return task  # idempotent
        current.append(depends_on_task_id)

        from db import migration_execution as _engine

        staged = [row.to_dict() for row in self.list_tasks(task.project_id)]
        for row in staged:
            if row["id"] == task_id:
                row["depends_on"] = current
        try:
            _engine.topological_stages(staged)
        except _engine.ExecutionPlanError as exc:
            raise ValueError(str(exc)) from exc
        task.depends_on = current
        self.session.flush()
        return task

    def auto_derive_dependencies(self, project_id: str) -> dict:
        """Derive task dependencies from system-level dependency edges.

        advanced/61 §4.2: auto-created tasks arrived unordered. If the
        graph says system A CALLS system B, every B-task becomes a
        dependency of every A-task — migrate the callee before the
        caller. Cycle-safe: derived edges are validated as one batch
        and rejected whole if they close a cycle.
        """
        from db import migration_execution as _engine

        rows = [row.to_dict() for row in self.list_tasks(project_id)]
        system_ids = {row["system_id"] for row in rows if row.get("system_id")}
        if not system_ids:
            return {"derived": 0, "edges": [], "note": "no tasks carry a system_id"}

        from db.repositories.system_repository import SystemRepository

        system_repo = SystemRepository(self.session)
        edges: list[dict] = []
        for system_id in sorted(system_ids):
            for edge in system_repo.dependencies_for(system_id):
                edges.append({"parent_id": edge.parent_id, "child_id": edge.child_id,
                              "relation": edge.relation or "CALLS"})

        derived = _engine.derive_system_dependencies(rows, edges)
        if not derived:
            return {"derived": 0, "edges": []}

        # validate the whole batch together before persisting anything
        staged = [dict(row) for row in rows]
        by_id = {row["id"]: row for row in staged}
        for item in derived:
            row = by_id[item["task_id"]]
            deps = set(row.get("depends_on") or []) | {item["depends_on_task_id"]}
            row["depends_on"] = sorted(deps)
        try:
            _engine.topological_stages(staged)
        except _engine.ExecutionPlanError as exc:
            raise ValueError(f"derived edges would close a cycle: {exc}") from exc

        for item in derived:
            row = by_id[item["task_id"]]
            deps = set(row.get("depends_on") or []) | {item["depends_on_task_id"]}
            self.update_task(item["task_id"], depends_on=sorted(deps))
        return {"derived": len(derived), "edges": derived}

    def execution_plan(self, project_id: str) -> dict:
        """Stages, parallelization, critical path, ready set, blockers."""
        from db import migration_execution as _engine

        rows = [row.to_dict() for row in self.list_tasks(project_id)]
        plan = _engine.execution_plan(rows)
        titles = {row["id"]: row["title"] for row in rows}
        for stage in plan["stages"]:
            stage["tasks"] = [
                {"task_id": tid, "title": titles.get(tid)} for tid in stage["task_ids"]
            ]
        plan["critical_path_titles"] = [titles.get(t) for t in plan["critical_path"]]
        plan["ready_now_titles"] = [titles.get(t) for t in plan["ready_now"]]
        return plan

    def start_task(self, task_id: str) -> MigrationTask:
        """Gate: only TODO tasks with all dependencies satisfied."""
        from db import migration_execution as _engine

        task = self.session.execute(select(MigrationTask).where(MigrationTask.id == task_id)).scalars().first()
        if task is None:
            raise ValueError("migration task not found")
        index = self._engine_index(task.project_id)
        allowed, blockers = _engine.can_start(index[task_id], index)
        if not allowed:
            detail = "; ".join(
                f"{b['task_id']} ({b['status']})" for b in blockers
            )
            raise _DependencyGateError(f"task is not startable — blocked by: {detail}",
                                       blockers=blockers)
        return self.update_task(task_id, status="IN_PROGRESS")

    def complete_task(self, task_id: str) -> MigrationTask:
        task = self.session.execute(select(MigrationTask).where(MigrationTask.id == task_id)).scalars().first()
        if task is None:
            raise ValueError("migration task not found")
        if task.status != "IN_PROGRESS":
            raise ValueError(f"only IN_PROGRESS tasks can complete (current: {task.status})")
        return self.update_task(task_id, status="DONE")

    def rollback_task(self, task_id: str, reason: str) -> dict:
        """Revert a finished/in-progress task; cascade per the plan.

        DONE/SKIPPED dependents roll back transitively; IN_PROGRESS
        dependents become BLOCKED with the reason naming the rollback.
        """
        from db import migration_execution as _engine

        if not (reason or "").strip():
            raise ValueError("rollback requires a reason")
        task = self.session.execute(select(MigrationTask).where(MigrationTask.id == task_id)).scalars().first()
        if task is None:
            raise ValueError("migration task not found")
        rows = [row.to_dict() for row in self.list_tasks(task.project_id)]
        plan = _engine.rollback_plan(task_id, rows)
        rolled_back, blocked = [], []
        for row_id in plan["rollback"]:
            self.update_task(row_id, status="TODO", blocked_reason=None)
            rolled_back.append(row_id)
        for row_id in plan["block"]:
            self.update_task(
                row_id, status="BLOCKED",
                blocked_reason=f"dependency {task_id} rolled back: {reason.strip()}",
            )
            blocked.append(row_id)
        return {
            "rolled_back": rolled_back,
            "blocked": blocked,
            "reason": reason.strip(),
            "task_id": task_id,
        }

    def advance_ready(self, project_id: str, *, limit: int = 25) -> dict:
        """Bulk-start the current ready set (wave kickoff)."""
        from db import migration_execution as _engine

        rows = [row.to_dict() for row in self.list_tasks(project_id)]
        ready = _engine.ready_set(rows)[:max(1, limit)]
        started = []
        for row_id in ready:
            self.update_task(row_id, status="IN_PROGRESS")
            started.append(row_id)
        return {"started": started, "count": len(started)}

    # ----------------------------------------------------- derived state

    def _task_rows(self, project_id: str) -> list[MigrationTask]:
        return self.list_tasks(project_id)

    def _refresh_project(self, project_id: str) -> None:
        """Recompute the project's progress + status from its tasks."""
        project = self.session.execute(select(MigrationProject).where(MigrationProject.id == project_id)).scalars().first()
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
        if self.session.execute(select(MigrationProject).where(MigrationProject.id == project_id)).scalars().first() is None:
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
