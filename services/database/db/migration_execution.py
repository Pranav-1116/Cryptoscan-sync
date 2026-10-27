"""Pure execution-engine core: ordering, gates, parallelization, rollback.

Lives beside ``MigrationTaskRepository`` in the shared db kernel so both
the API service and worker contexts import it without a layering
inversion (db must never import api).

Task dicts need at least: ``id``, ``status``, and optionally
``depends_on`` (list of task ids that must finish first), ``system_id``,
``priority``, ``title``. Unknown dependency references are reported,
never silently dropped on the floor.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

# Terminal-but-satisfying statuses: a dependent may start once every
# dependency is DONE or was SKIPPED (a skipped task is consciously
# withdrawn, so it cannot block the chain forever).
SATISFYING = {"DONE", "SKIPPED"}
ACTIVE = {"TODO", "IN_PROGRESS", "BLOCKED"}

# Allowed transitions of the execution state machine. DONE -> TODO and
# SKIPPED -> TODO exist ONLY through the explicit rollback path (the
# caller must supply a reason), which is why can_transition reports
# them separately from the plain matrix.
_TRANSITIONS: dict[str, set[str]] = {
    "TODO": {"IN_PROGRESS", "BLOCKED", "SKIPPED", "TODO"},
    "IN_PROGRESS": {"DONE", "BLOCKED", "TODO", "IN_PROGRESS"},
    "DONE": {"DONE"},  # DONE -> TODO is rollback-only
    "BLOCKED": {"TODO", "IN_PROGRESS", "SKIPPED", "BLOCKED"},
    "SKIPPED": {"SKIPPED"},  # SKIPPED -> TODO is rollback-only
}

_VALID = set(_TRANSITIONS)


class ExecutionPlanError(ValueError):
    """Invalid plan input: cycle, unknown reference, bad transition."""


def _status(task: Mapping[str, Any]) -> str:
    return str(task.get("status") or "TODO").upper()


def _deps(task: Mapping[str, Any]) -> list[str]:
    raw = task.get("depends_on") or []
    if isinstance(raw, str):
        raw = [raw]
    return [str(ref) for ref in raw if str(ref).strip()]


def index_tasks(tasks: Iterable[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    """Task id -> task dict; rejects duplicates (ambiguous plan input)."""
    out: dict[str, dict[str, Any]] = {}
    for task in tasks or []:
        task_id = str(task.get("id") or "").strip()
        if not task_id:
            raise ExecutionPlanError("task without id")
        if task_id in out:
            raise ExecutionPlanError(f"duplicate task id {task_id}")
        out[task_id] = dict(task)
    return out


def unknown_dependencies(index: Mapping[str, dict[str, Any]]) -> dict[str, list[str]]:
    """Per task: dependency references that point at nothing.

    A dangling reference would otherwise make the task permanently
    un-ready, so it is surfaced instead of dropped.
    """
    return {
        task_id: [ref for ref in _deps(task) if ref not in index]
        for task_id, task in index.items()
        if any(ref not in index for ref in _deps(task))
    }


def dependency_graph(index: Mapping[str, dict[str, Any]]) -> dict[str, set[str]]:
    """task id -> set of dependency ids (edges point dep -> dependent)."""
    return {task_id: set(_deps(task)) for task_id, task in index.items()}


def _find_cycle(index: Mapping[str, dict[str, Any]]) -> list[str] | None:
    """Return one dependency cycle as [a, b, ..., a], or None."""
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {task_id: WHITE for task_id in index}
    stack: list[str] = []

    def visit(node: str) -> list[str] | None:
        color[node] = GRAY
        stack.append(node)
        for dep in sorted(_deps(index[node])):
            if dep not in index:
                continue  # reported separately as unknown
            if color[dep] == GRAY:
                cycle_at = stack.index(dep)
                return stack[cycle_at:] + [dep]
            if color[dep] == WHITE:
                found = visit(dep)
                if found:
                    return found
        stack.pop()
        color[node] = BLACK
        return None

    for task_id in sorted(index):
        if color[task_id] == WHITE:
            found = visit(task_id)
            if found:
                return found
    return None


def topological_stages(tasks: Iterable[Mapping[str, Any]]) -> list[list[str]]:
    """Kahn staging: stage N holds tasks whose deps all live in stages < N.

    Every task in a stage is parallelizable with its stage siblings —
    this IS the parallelization analysis advanced/61 §4.2 asked for.
    Raises ExecutionPlanError on a dependency cycle (with the cycle
    path) rather than returning a silently truncated plan.
    """
    index = index_tasks(tasks)
    cycle = _find_cycle(index)
    if cycle:
        raise ExecutionPlanError("dependency cycle: " + " -> ".join(cycle))
    remaining = dict(dependency_graph(index))
    placed: set[str] = set()
    stages: list[list[str]] = []
    while remaining:
        ready = sorted(
            task_id for task_id, deps in remaining.items() if deps <= placed
        )
        if not ready:  # defensive: cycles are detected above
            raise ExecutionPlanError("unsatisfiable dependencies remain")
        stages.append(ready)
        for task_id in ready:
            placed.add(task_id)
            del remaining[task_id]
    return stages


def _depth(index: Mapping[str, dict[str, Any]], memo: dict[str, int], task_id: str) -> int:
    if task_id in memo:
        return memo[task_id]
    deps = [dep for dep in _deps(index[task_id]) if dep in index]
    memo[task_id] = 1 + (max((_depth(index, memo, dep) for dep in deps), default=0))
    return memo[task_id]


def critical_path(tasks: Iterable[Mapping[str, Any]]) -> list[str]:
    """Longest dependency chain (by task count), ordered root -> leaf.

    The chain that cannot be parallelized away — extending it by one
    day extends the whole project.
    """
    index = index_tasks(tasks)
    memo: dict[str, int] = {}
    leaf = max(index, key=lambda t: _depth(index, memo, t)) if index else None
    if leaf is None:
        return []
    path = [leaf]
    deps = [dep for dep in _deps(index[leaf]) if dep in index]
    while deps:
        best = max(deps, key=lambda d: memo.get(d, 0))
        path.append(best)
        deps = [dep for dep in _deps(index[best]) if dep in index]
    path.reverse()
    return path


def blocking_tasks(task: Mapping[str, Any], index: Mapping[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Unsatisfied dependencies of ``task`` (id, title, status, chain)."""
    out: list[dict[str, Any]] = []
    for ref in _deps(task):
        dep = index.get(ref)
        if dep is None:
            out.append({"task_id": ref, "title": None, "status": "UNKNOWN", "chain": [ref]})
            continue
        if _status(dep) in SATISFYING:
            continue
        # walk down to the root cause: a BLOCKED dependency reports the
        # blocked chain, not just itself
        chain = [ref]
        cursor = dep
        seen = {ref}
        while _status(cursor) == "BLOCKED":
            deeper = [d for d in _deps(cursor) if d in index and d not in seen]
            if not deeper:
                break
            nxt = index[deeper[0]]
            if _status(nxt) in SATISFYING:
                break
            seen.add(deeper[0])
            chain.append(deeper[0])
            cursor = nxt
        out.append({"task_id": ref, "title": dep.get("title"), "status": _status(dep), "chain": chain})
    return out


def ready_set(tasks: Iterable[Mapping[str, Any]]) -> list[str]:
    """Ids of TODO tasks whose dependencies are all satisfied."""
    index = index_tasks(tasks)
    return sorted(
        task_id
        for task_id, task in index.items()
        if _status(task) == "TODO"
        and all(
            _status(index[ref]) in SATISFYING
            for ref in _deps(task)
            if ref in index
        )
    )


def validate_transition(current: str, new: str) -> tuple[bool, str]:
    """State-machine gate. Returns (allowed, reason).

    DONE/SKIPPED -> TODO is reported as allowed only under the
    ``rollback`` flag of :func:`validate_transition_ex` — plain callers
    (repository ``update_task``) keep the stricter rule.
    """
    current_n = str(current or "TODO").upper()
    new_n = str(new or "").upper()
    if current_n not in _VALID:
        return False, f"unknown current status '{current_n}'"
    if new_n not in _VALID:
        return False, f"unknown target status '{new_n}'"
    if new_n not in _TRANSITIONS[current_n]:
        return False, f"cannot move {current_n} -> {new_n}"
    return True, ""


def validate_transition_ex(current: str, new: str, *, rollback: bool = False) -> tuple[bool, str]:
    """Like :func:`validate_transition` but permits DONE/SKIPPED -> TODO
    when the caller is the explicit rollback path (reason required)."""
    allowed, reason = validate_transition(current, new)
    if allowed:
        return allowed, reason
    current_n = str(current or "").upper()
    new_n = str(new or "").upper()
    if rollback and new_n == "TODO" and current_n in {"DONE", "SKIPPED"}:
        return True, ""
    return allowed, reason


def can_start(task: Mapping[str, Any], index: Mapping[str, dict[str, Any]]) -> tuple[bool, list[dict[str, Any]]]:
    """Execution gate: TODO + every dependency satisfied."""
    if _status(task) != "TODO":
        return False, [{"task_id": task.get("id"), "title": task.get("title"),
                        "status": _status(task), "chain": [task.get("id")]}]
    blockers = blocking_tasks(task, index)
    return (not blockers, blockers)


def rollback_plan(
    task_id: str,
    tasks: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """What a rollback of ``task_id`` must do, without executing it.

    A completed task may have dependents that already started or
    finished on top of it. The plan cascades: finished dependents roll
    back too (transitively); in-progress dependents become BLOCKED
    with the reason naming the rolled-back dependency. Merely-TODO
    dependents need no change (they were never allowed to start).
    """
    index = index_tasks(tasks)
    if task_id not in index:
        raise ExecutionPlanError(f"unknown task {task_id}")
    task = index[task_id]
    if _status(task) not in {"DONE", "SKIPPED", "IN_PROGRESS"}:
        return {
            "task_id": task_id,
            "status": _status(task),
            "rollback": [],
            "block": [],
            "reason_needed": True,
            "note": "only DONE, SKIPPED, or IN_PROGRESS tasks can roll back",
        }

    # dependents = tasks that (transitively) depend on task_id
    dependents: dict[str, set[str]] = dependency_graph(index)
    reversed_deps: dict[str, set[str]] = {}
    for dependent, deps in dependents.items():
        for dep in deps:
            reversed_deps.setdefault(dep, set()).add(dependent)

    rollback: list[str] = [task_id]
    block: list[str] = []
    frontier = [task_id]
    seen = {task_id}
    while frontier:
        current = frontier.pop()
        for dependent in sorted(reversed_deps.get(current, ())):
            if dependent in seen:
                continue
            seen.add(dependent)
            status = _status(index[dependent])
            if status in {"DONE", "SKIPPED"}:
                rollback.append(dependent)
                frontier.append(dependent)  # its own dependents cascade
            elif status == "IN_PROGRESS":
                block.append(dependent)
    return {
        "task_id": task_id,
        "status": _status(task),
        "rollback": rollback,
        "block": block,
        "reason_needed": True,
    }


def execution_plan(tasks: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Full execution plan: stages, parallelization, critical path,
    ready set, blockers, unknown references."""
    index = index_tasks(tasks)
    try:
        stages = topological_stages(index.values())
        cycle = None
    except ExecutionPlanError as exc:
        stages = []
        cycle = str(exc)
    unknown = unknown_dependencies(index)
    blockers = {
        task_id: blocking_tasks(task, index)
        for task_id, task in index.items()
        if _status(task) == "TODO" and blocking_tasks(task, index)
    }
    by_stage: dict[str, int] = {}
    for number, stage in enumerate(stages):
        for task_id in stage:
            by_stage[task_id] = number
    path = critical_path(index.values()) if not cycle else []
    return {
        "tasks_total": len(index),
        "stages": [
            {
                "stage": number,
                "parallelizable": len(stage) > 1,
                "task_ids": stage,
            }
            for number, stage in enumerate(stages)
        ],
        "stage_of_task": by_stage,
        "max_parallelism": max((len(s) for s in stages), default=0),
        "critical_path": path,
        "critical_path_length": len(path),
        "ready_now": ready_set(index.values()),
        "blocked_tasks": blockers,
        "unknown_dependencies": unknown,
        "cycle": cycle,
        "status_counts": {
            status: sum(1 for t in index.values() if _status(t) == status)
            for status in ("TODO", "IN_PROGRESS", "DONE", "BLOCKED", "SKIPPED")
        },
    }


def derive_system_dependencies(
    tasks: Iterable[Mapping[str, Any]],
    system_edges: Iterable[Mapping[str, Any]],
) -> list[dict[str, str]]:
    """Derive task dependencies from system-level dependency edges.

    ``system_edges`` items are {parent_id, child_id, relation}: parent
    depends on child (parent CALLS child). A migration of the parent
    system can only land after the dependency it calls is migrated, so
    for every task pair (on parent, on child) a child-task -> parent-
    task dependency is derived. Cycles are NOT created here; the caller
    validates with :func:`topological_stages` before persisting.
    """
    index = index_tasks(tasks)
    by_system: dict[str, list[str]] = {}
    for task_id, task in index.items():
        system_id = task.get("system_id")
        if system_id:
            by_system.setdefault(str(system_id), []).append(task_id)

    derived: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for edge in system_edges or []:
        parent = str(edge.get("parent_id") or "")
        child = str(edge.get("child_id") or "")
        relation = str(edge.get("relation") or "CALLS")
        if not parent or not child or parent == child:
            continue
        for child_task in by_system.get(child, ()):
            for parent_task in by_system.get(parent, ()):
                if child_task == parent_task:
                    continue
                key = (child_task, parent_task)
                if key in seen:
                    continue
                seen.add(key)
                derived.append({
                    "depends_on_task_id": child_task,
                    "task_id": parent_task,
                    "reason": f"system {parent} {relation} system {child}",
                })
    return derived
