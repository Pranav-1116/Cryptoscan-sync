"""Inventory completeness: empty, partial and complete are three different answers.

A component with no cryptography found is not "a component without cryptography".
Between the two statements sit three questions:

* **was the component inspected at all** — a component nobody scanned contributes a
  row to the inventory and no knowledge to it;
* **did every task that ran finish** — a scan that timed out on a vendored
  directory inspected the component partially, and the part it skipped is exactly
  where old crypto lives;
* **do the tasks agree** — one tool reporting an algorithm the other could not
  see is not a tie to be averaged; it is a contradiction to be reported.

The review's point is that a bank's CBOM is read as a statement about coverage, so
"we found no AES-128-CBC" and "we did not look" must never render the same way.

This module answers one component at a time and refuses three tempting collapses:

1. **unmeasured is not clean** — a component with no task is ``UNMEASURED``, and
   its absence of findings says nothing;
2. **partial is not complete** — one unfinished task makes the component
   ``INCOMPLETE``, whatever the finished ones found;
3. **a contradiction is not a majority** — tasks that disagree produce
   ``CONTRADICTED`` with both evidence ids, never the more convenient answer.

``quotable`` then says which components may be counted in a total, so a summary
that says "40 of 40 systems have a complete CBOM" can be checked against the rows
it was built from.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

SCHEMA = "cryptoscan.cbom-inventory-completeness/1"

#: Per-component states, weakest first. ``COMPLETE`` is the only quotable one.
STATES: tuple[str, ...] = ("UNMEASURED", "INCOMPLETE", "EMPTY", "CONTRADICTED", "COMPLETE")

#: A task whose own status is any of these did not finish.
UNFINISHED: frozenset[str] = frozenset({
    "TIMEOUT", "TIMED_OUT", "FAILED", "ERROR", "SKIPPED", "CANCELLED", "PARTIAL",
    "ABORTED", "PENDING", "RUNNING", "UNKNOWN",
})

#: States that may be counted when a total is claimed. ``EMPTY`` belongs here: every
#: task finished and found nothing, which is a measurement. ``UNMEASURED``,
#: ``INCOMPLETE`` and ``CONTRADICTED`` do not, because nobody knows enough about them.
QUOTABLE: frozenset[str] = frozenset({"COMPLETE", "EMPTY"})

#: How a claim about "no cryptography" must be read, per state.
READING: dict[str, str] = {
    "UNMEASURED": "nobody looked, so the absence of findings is not evidence of absence",
    "INCOMPLETE": "part of the component was not inspected, so the absence of findings "
                  "covers only the part that was",
    "EMPTY": "every task finished and found nothing, which is a measurement",
    "CONTRADICTED": "the tasks disagree, so neither the findings nor the absence of them "
                    "is settled",
    "COMPLETE": "every task finished and the findings are the component's inventory",
}


def _task_state(task: Mapping[str, Any]) -> str:
    status = str(task.get("status") or "").strip().upper()
    if not status:
        return "UNKNOWN"
    return status


def _task_id(task: Mapping[str, Any], index: int) -> str:
    return str(task.get("task") or task.get("name") or task.get("tool")
               or f"task-{index}")


def component(claims: Iterable[Mapping[str, Any]],
              tasks: Iterable[Mapping[str, Any]] | None = None, *,
              name: str | None = None) -> dict[str, Any]:
    """One component's completeness, from what ran and what it reported.

    ``tasks`` are the jobs the platform attempted against the component:
    ``{"task": "syft-sbom", "status": "COMPLETE"}``. ``claims`` are what the tasks
    found, each carrying the task that produced it::

        {"task": "semgrep-crypto", "algorithm": "AES-128-CBC", "evidence_id": "EV-1"}

    A claim from a task that never finished is kept as a **candidate**, never as a
    finding: the row exists and cannot be quoted.
    """
    task_rows: list[dict[str, Any]] = []
    for index, task in enumerate(tasks or (), start=1):
        if not isinstance(task, Mapping):
            continue
        state = _task_state(task)
        task_rows.append({
            "task": _task_id(task, index),
            "status": state,
            "finished": state in {"COMPLETE", "OK", "SUCCESS", "DONE", "FINISHED"},
            "found": task.get("found"),
            "reason": task.get("reason"),
            "evidence_id": task.get("evidence_id"),
        })
    finished = {row["task"] for row in task_rows if row["finished"]}
    unfinished = [row for row in task_rows if not row["finished"]]

    findings: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    refused: list[dict[str, Any]] = []
    for claim in claims or ():
        if not isinstance(claim, Mapping):
            refused.append({"claim": claim, "reason": "a claim must be an object"})
            continue
        algorithm = str(claim.get("algorithm") or "").strip()
        if not algorithm:
            refused.append({"claim": dict(claim), "reason": "a claim with no algorithm"})
            continue
        task = str(claim.get("task") or "").strip()
        row = {"algorithm": algorithm, "task": task or None,
               "evidence_id": str(claim.get("evidence_id") or "") or None,
               "location": claim.get("location") or claim.get("file_path")}
        if not task:
            refused.append({"claim": row,
                            "reason": "a claim that names no task cannot be weighed "
                                      "against the tasks that ran"})
            continue
        if row["evidence_id"] is None:
            refused.append({"claim": row, "reason": "the claim has no evidence id"})
            continue
        if task in finished:
            findings.append(row)
        elif task_rows and task not in {item["task"] for item in task_rows}:
            # a task nobody recorded running cannot have produced a finding
            refused.append({**row, "reason": "the claim names a task that never ran on "
                                             "this component"})
        else:
            candidates.append({**row, "reason": "the task did not finish, so its finding "
                                                "is a candidate and not quotable"})

    by_algorithm: dict[str, dict[str, Any]] = {}
    for row in findings:
        entry = by_algorithm.setdefault(row["algorithm"], {"algorithm": row["algorithm"],
                                                           "tasks": [], "evidence_ids": []})
        if row["task"] not in entry["tasks"]:
            entry["tasks"].append(row["task"])
        if row["evidence_id"] not in entry["evidence_ids"]:
            entry["evidence_ids"].append(row["evidence_id"])

    contradictions = _contradictions(task_rows, by_algorithm, finished)

    if not task_rows:
        state = "UNMEASURED"
    elif unfinished:
        state = "INCOMPLETE"
    elif contradictions:
        state = "CONTRADICTED"
    elif not findings:
        state = "EMPTY"
    else:
        state = "COMPLETE"

    return {
        "schema": SCHEMA,
        "component": name,
        "state": state,
        "quotable": state in QUOTABLE,
        "reading": READING[state],
        "tasks": task_rows,
        "finished_tasks": sorted(finished),
        "unfinished_tasks": unfinished,
        "findings": findings,
        "candidates": candidates,
        "refused": refused,
        "algorithms": sorted(by_algorithm),
        "by_algorithm": [by_algorithm[algorithm] for algorithm in sorted(by_algorithm)],
        "contradictions": contradictions,
        "statement": _statement(name, state, task_rows, findings, unfinished,
                                contradictions),
    }


def _contradictions(task_rows: list[Mapping[str, Any]],
                    by_algorithm: Mapping[str, Mapping[str, Any]],
                    finished: set[str]) -> list[dict[str, Any]]:
    """A task that finished and reported "nothing" while another reported a finding."""
    reported_empty = {str(row["task"]) for row in task_rows
                      if row.get("finished") and row.get("found") is False}
    contradictions: list[dict[str, Any]] = []
    for task in sorted(reported_empty):
        for algorithm, entry in by_algorithm.items():
            others = [name for name in entry["tasks"] if name != task]
            if not others:
                continue
            contradictions.append({
                "kind": "REPORTED_EMPTY_AND_FOUND",
                "algorithm": algorithm,
                "empty_from": task,
                "found_by": others,
                "evidence_ids": list(entry["evidence_ids"]),
                "statement": (f"{task} reported no cryptography while "
                              f"{', '.join(others)} reported {algorithm}; the "
                              "disagreement is reported, not averaged"),
            })
    return contradictions


def _statement(name: str | None, state: str, tasks: list[Mapping[str, Any]],
               findings: list[Mapping[str, Any]], unfinished: list[Mapping[str, Any]],
               contradictions: list[Mapping[str, Any]]) -> str:
    who = name or "this component"
    if state == "UNMEASURED":
        return f"{who} was never inspected; no task ran, so nothing is claimed about it"
    if state == "INCOMPLETE":
        missing = ", ".join(str(row["task"]) for row in unfinished)
        return (f"{who} is partly inspected: {missing} did not finish, so the "
                f"{len(findings)} finding(s) cover only the part that was")
    if state == "CONTRADICTED":
        return (f"{who} has {len(contradictions)} contradiction(s) between tasks that "
                "finished; neither the findings nor their absence is settled")
    if state == "EMPTY":
        return (f"{who}: every one of {len(tasks)} task(s) finished and none found "
                "cryptography, which is a measurement and not an assumption")
    return (f"{who}: {len(tasks)} task(s) finished and produced {len(findings)} finding(s) "
            "across " + (", ".join(sorted({str(row['algorithm'])
                                          for row in findings})) or "no algorithm"))


def inventory(components: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Every component's state, and the only total that may be quoted from them."""
    rows = [row for row in components or () if isinstance(row, Mapping)]
    counts: dict[str, int] = {state: 0 for state in STATES}
    for row in rows:
        counts[str(row.get("state"))] = counts.get(str(row.get("state")), 0) + 1
    quotable = [row for row in rows if row.get("state") in QUOTABLE]
    complete = counts.get("COMPLETE", 0)
    settled = len(quotable) == len(rows)
    return {
        "schema": SCHEMA,
        "components": len(rows),
        "counts": dict(sorted(counts.items())),
        "quotable": len(quotable),
        "measured": len(rows) - counts.get("UNMEASURED", 0),
        "complete_share": round(100.0 * complete / len(rows), 1) if rows else 0.0,
        "may_report_total": bool(rows) and settled,
        "unmeasurable": [row.get("component") for row in rows
                         if row.get("state") == "UNMEASURED"],
        "statement": (
            f"{len(rows)} component(s): {complete} complete, "
            f"{counts.get('EMPTY', 0)} empty, {counts.get('INCOMPLETE', 0)} incomplete, "
            f"{counts.get('CONTRADICTED', 0)} contradicted, "
            f"{counts.get('UNMEASURED', 0)} unmeasured"
            + ("; every component is settled (complete or measured empty), so a total "
               "may be quoted" if rows and settled else
               "; no total may be quoted for the inventory")),
    }
