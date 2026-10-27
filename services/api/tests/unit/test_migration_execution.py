"""Migration execution engine — pure ordering/gating/rollback rules.

Round 30 build of advanced/61 §4.2 (dependency-aware ordering,
parallelization analysis, rollback plan) and §5 (execution engine, not
tracking-only) + deep/29 §9.2.
"""

from __future__ import annotations

import pytest

from db import migration_execution as engine


def task(tid, status="TODO", depends_on=(), system_id=None, title=None):
    return {"id": tid, "status": status, "depends_on": list(depends_on),
            "system_id": system_id, "title": title or f"task {tid}"}


# ── staging + parallelization ────────────────────────────────────────


def test_stages_group_parallelizable_tasks():
    tasks = [
        task("a"), task("b"),                      # no deps → stage 0
        task("c", depends_on=["a", "b"]),          # stage 1
        task("d", depends_on=["c"]),               # stage 2
        task("e", depends_on=["c"]),               # stage 2 (parallel with d)
    ]
    stages = engine.topological_stages(tasks)
    assert stages == [["a", "b"], ["c"], ["d", "e"]]


def test_cycle_is_rejected_with_the_path():
    tasks = [task("a", depends_on=["c"]), task("b", depends_on=["a"]),
             task("c", depends_on=["b"])]
    with pytest.raises(engine.ExecutionPlanError) as exc:
        engine.topological_stages(tasks)
    assert "cycle" in str(exc.value)
    assert "->" in str(exc.value)


def test_unknown_dependency_reference_is_surfaced():
    tasks = [task("a", depends_on=["ghost"])]
    unknown = engine.unknown_dependencies(engine.index_tasks(tasks))
    assert unknown == {"a": ["ghost"]}
    plan = engine.execution_plan(tasks)
    assert plan["unknown_dependencies"] == {"a": ["ghost"]}
    # the plan still computes; the dangling edge is visible, not dropped
    assert plan["blocked_tasks"]["a"][0]["status"] == "UNKNOWN"


def test_skipped_dependency_satisfies_dependents():
    tasks = [task("a", status="SKIPPED"), task("b", depends_on=["a"])]
    assert engine.ready_set(tasks) == ["b"]


# ── critical path ────────────────────────────────────────────────────


def test_critical_path_is_the_longest_chain():
    tasks = [
        task("root"), task("mid", depends_on=["root"]),
        task("leaf", depends_on=["mid"]),
        task("side"),                       # parallel branch, shorter
        task("leaf2", depends_on=["side"]),
    ]
    assert engine.critical_path(tasks) == ["root", "mid", "leaf"]


# ── start gate ───────────────────────────────────────────────────────


def test_start_gate_blocks_on_unfinished_dependency():
    tasks = [task("dep", status="TODO"), task("a", depends_on=["dep"])]
    allowed, blockers = engine.can_start(tasks[1], engine.index_tasks(tasks))
    assert not allowed
    assert blockers[0]["task_id"] == "dep"
    assert blockers[0]["status"] == "TODO"


def test_start_gate_reports_blocked_chain_to_root_cause():
    tasks = [
        task("root", status="BLOCKED"),
        task("mid", status="BLOCKED", depends_on=["root"]),
        task("leaf", depends_on=["mid"]),
    ]
    allowed, blockers = engine.can_start(tasks[2], engine.index_tasks(tasks))
    assert not allowed
    chain = blockers[0]["chain"]
    assert chain[0] == "mid" and chain[-1] == "root"


def test_start_gate_refuses_non_todo_tasks():
    tasks = [task("a", status="IN_PROGRESS")]
    allowed, _ = engine.can_start(tasks[0], engine.index_tasks(tasks))
    assert not allowed


# ── transition matrix ────────────────────────────────────────────────


def test_transition_rules():
    assert engine.validate_transition("TODO", "IN_PROGRESS") == (True, "")
    assert engine.validate_transition("IN_PROGRESS", "DONE") == (True, "")
    ok, reason = engine.validate_transition("TODO", "DONE")
    assert not ok and "TODO -> DONE" in reason
    ok, _ = engine.validate_transition("DONE", "TODO")
    assert not ok  # plain path refuses
    ok, _ = engine.validate_transition_ex("DONE", "TODO", rollback=True)
    assert ok      # explicit rollback path allows
    ok, reason = engine.validate_transition("TODO", "BOGUS")
    assert not ok and "unknown target status" in reason


# ── rollback plan ────────────────────────────────────────────────────


def test_rollback_cascades_done_and_blocks_in_progress():
    tasks = [
        task("base", status="DONE"),
        task("done_dep", status="DONE", depends_on=["base"]),
        task("deep_dep", status="DONE", depends_on=["done_dep"]),
        task("running", status="IN_PROGRESS", depends_on=["base"]),
        task("waiting", status="TODO", depends_on=["base"]),
    ]
    plan = engine.rollback_plan("base", tasks)
    assert plan["rollback"] == ["base", "done_dep", "deep_dep"]
    assert plan["block"] == ["running"]
    assert "waiting" not in plan["rollback"] + plan["block"]


def test_rollback_of_todo_task_is_a_no_op_plan():
    plan = engine.rollback_plan("a", [task("a")])
    assert plan["rollback"] == [] and plan["block"] == []
    assert "only DONE" in plan["note"]


# ── system-edge derivation ───────────────────────────────────────────


def test_system_edges_derive_task_ordering():
    tasks = [
        task("caller-task", system_id="sys-caller"),
        task("callee-task", system_id="sys-callee"),
        task("bystander", system_id="sys-other"),
    ]
    edges = [{"parent_id": "sys-caller", "child_id": "sys-callee", "relation": "CALLS"}]
    derived = engine.derive_system_dependencies(tasks, edges)
    assert derived == [
        {"depends_on_task_id": "callee-task", "task_id": "caller-task",
         "reason": "system sys-caller CALLS system sys-callee"},
    ]
    staged = [dict(t) for t in tasks]
    staged[0]["depends_on"] = ["callee-task"]
    assert engine.topological_stages(staged) == [["bystander", "callee-task"], ["caller-task"]]


def test_system_edges_ignore_self_and_unrelated():
    derived = engine.derive_system_dependencies(
        [task("a", system_id="s1")],
        [{"parent_id": "s1", "child_id": "s1", "relation": "CALLS"}],
    )
    assert derived == []


# ── full plan ────────────────────────────────────────────────────────


def test_execution_plan_shape():
    tasks = [
        task("a"), task("b"),
        task("c", depends_on=["a", "b"]),
        task("d", status="IN_PROGRESS"),
        task("e", status="BLOCKED"),
        task("f", status="DONE"),
    ]
    plan = engine.execution_plan(tasks)
    assert plan["tasks_total"] == 6
    assert plan["stages"][0]["parallelizable"] is True
    # structural parallelism: stage 0 holds every dep-free task
    # (a, b, d, e, f) regardless of execution state; ready_now is the
    # execution-state view (only TODO tasks may actually start)
    assert plan["max_parallelism"] == 5
    assert plan["critical_path"][0] in {"a", "b"}
    assert plan["status_counts"] == {"TODO": 3, "IN_PROGRESS": 1, "DONE": 1,
                                     "BLOCKED": 1, "SKIPPED": 0}
    assert plan["ready_now"] == ["a", "b"]
