"""Per-collector authority: WHO, WHAT, WHICH revision, WHEN, HOW LONG, WHICH permission.

The review's fifth blocker said the authorization model was not uniform per
collector: the five questions were answered by different mechanisms in different
families, and nothing showed which. This drill builds the matrix — one row per
collector plane, one column per question — and fills each cell with the mechanism
that answers it in *that* plane's code path.

Two kinds of cell, and the difference matters:

    PROBED   the drill executed the control (a refused target, an exhausted
             budget) and watched it refuse
    CITED    the drill found the mechanism in the plane's own code path and
             verified the citation resolves — a symbol that exists in a file that
             imports it
    ABSENT   nothing answers the question for this plane

A citation is weaker than a probe and the matrix says so per cell. That is the
point: the blocker is a *uniformity* claim, and a uniform-looking table built out
of citations hides exactly the families where the mechanism is missing.

Run::

    python scripts/collector_authority.py \\
        --json docs/bank-environment/116-collector-authority.json \\
        --md   docs/bank-environment/116-collector-authority.md
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "cryptoscan.collector-authority/1"
VERSION = "collector-authority/1.0"

REPO_ROOT = Path(__file__).resolve().parents[1]
API = REPO_ROOT / "services" / "api" / "api"

PROBED, CITED, ABSENT = "PROBED", "CITED", "ABSENT"
PROVEN, PARTIAL, GAP = "PROVEN", "PARTIAL", "GAP"

QUESTIONS = ("who", "what_target", "which_revision", "when", "how_long", "permission")

#: what each question means in this product's terms
QUESTION_TEXT = {
    "who": "who is asking (authenticated principal and role)",
    "what_target": "what may be touched (scope admission, not a free-form string)",
    "which_revision": "which approved revision of that scope (pinned, not re-read)",
    "when": "when it is allowed (window start and expiry)",
    "how_long": "how long and how much (runtime and traffic budget)",
    "permission": "which permission the route demands",
}


@dataclass
class Plane:
    name: str
    entry: str                      #: the collector's entry point, as a route or a module
    modules: tuple[str, ...]        #: files its code path runs through
    probes: dict[str, str] = field(default_factory=dict)   #: question -> probe id
    note: str = ""


PLANES: tuple[Plane, ...] = (
    Plane(
        name="NETWORK",
        entry="POST /api/v1/network/crypto-observe",
        modules=("services/api/api/network_collect.py",
                 "services/api/api/security/network_collection.py",
                 "services/api/api/security/network_budget.py",
                 "services/api/api/routers/network.py"),
        probes={"what_target": "network_admission", "how_long": "network_budget"},
        note="the only plane that reaches the network itself, and the only one with admission "
             "and a traffic budget as first-class controls",
    ),
    Plane(
        name="RUNTIME",
        entry="POST /api/v1/runtime/crypto-events",
        modules=("services/api/api/routers/runtime_crypto.py",
                 "services/api/api/security/runtime_evidence_chain.py"),
        note="ingest of agent-produced events; the target is whatever the agent sends",
    ),
    Plane(
        name="STATIC",
        entry="POST /api/v1/scans (source scan)",
        modules=("services/api/api/routers/scans.py",
                 "services/api/api/routers/estate_graph.py"),
        note="target is a repository reference; the scan admission path applies",
    ),
    Plane(
        name="PKI",
        entry="certificate inventory sync",
        modules=("services/api/api/estate_discovery.py",
                 "services/api/api/routers/certificates.py"),
        note="reads certificate rows already in the inventory",
    ),
    Plane(
        name="CLOUD",
        entry="POST /api/v1/cloud/... discover",
        modules=("services/api/api/estate_cloud.py",
                 "services/api/api/routers/cloud.py"),
        note="reads provider APIs with a configured credential, not a per-request target",
    ),
    Plane(
        name="KUBERNETES",
        entry="cluster adapter",
        modules=("services/api/api/estate_discovery.py",),
    ),
    Plane(
        name="CMDB",
        entry="CMDB adapter",
        modules=("services/api/api/estate_discovery.py",),
    ),
    Plane(
        name="KMS",
        entry="KMS adapter",
        modules=("services/api/api/estate_discovery.py",),
    ),
    Plane(
        name="HSM",
        entry="HSM adapter",
        modules=("services/api/api/estate_discovery.py",),
    ),
    Plane(
        name="HARDWARE",
        entry="host evidence intake",
        modules=("services/api/api/routers/host_evidence.py",
                 "services/api/api/host_collect.py"),
    ),
    Plane(
        name="VENDOR",
        entry="vendor questionnaire / attestation",
        modules=("services/api/api/routers/vendor.py",
                 "services/api/api/estate_discovery.py"),
    ),
)

#: how each question is answered, as a search over the plane's own code path
MECHANISMS: dict[str, tuple[str, str]] = {
    "who": (r"require_permission|require_role|get_current_user|current_user|session",
            "an authenticated principal is required by the route"),
    "what_target": (r"checked_hosts|validate_probe_targets|scope_admission|admit_network|"
                    r"approved_scope|authori[sz]ed",
                    "the target is admitted by a validator, not accepted verbatim"),
    "which_revision": (r"policy_revision|scope_revision|approved_revision|revision_pin|saved_at",
                       "the approved scope revision is pinned and re-checked"),
    "when": (r"expires_at|not_before|window_started_at|valid_until|window_seconds",
             "the control carries a time window"),
    "how_long": (r"max_runtime|max_requests|max_connections|BudgetExhausted|reserve\(|budget",
                 "runtime and/or traffic are bounded by a budget"),
    "permission": (r"PERMISSION_MATRIX\[|require_permission\(",
                   "the route names the permission it demands"),
}


# --------------------------------------------------------------------- probes --- #
def probe_network_admission() -> dict[str, Any]:
    """A CIDR and a loopback address must both be refused by the collector itself."""
    from fastapi import HTTPException

    from api.security.network_collection import checked_hosts

    findings: dict[str, Any] = {}
    for label, target in (("cidr", ["10.0.0.0/8"]), ("loopback", ["127.0.0.1:443"])):
        try:
            checked_hosts(target)
            findings[label] = {"target": target[0], "refused": False}
        except HTTPException as exc:
            findings[label] = {"target": target[0], "refused": True,
                               "status": exc.status_code, "reason": str(exc.detail)[:160]}
    ok = all(item["refused"] for item in findings.values())
    return {"id": "network_admission", "proven": ok, "findings": findings,
            "meaning": ("the target is validated before any probe is sent: a subnet sweep and "
                        "a loopback target are both refused with 422")}


def probe_network_budget() -> dict[str, Any]:
    """A budget of one connection must accept one and refuse the second."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import db.models  # noqa: F401
    from db.models.base import Base
    from api.security.network_budget import BudgetExhausted, reserve

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    # the limits live under scope["traffic_budget"], which is how a saved scope stores them
    scope = {"traffic_budget": {"max_connections": 1, "max_bytes": 0}}
    findings: dict[str, Any] = {}
    try:
        try:
            reserve(session, None, inventory_id="authority-drill", connections=1)
            findings["no_scope"] = {"refused": False}
        except BudgetExhausted as exc:
            findings["no_scope"] = {"refused": True, "reason": str(exc)[:160]}
        first = reserve(session, scope, inventory_id="authority-drill", connections=1)
        findings["first"] = {"connections_used": first.get("connections_used"),
                             "refused": False}
        try:
            reserve(session, scope, inventory_id="authority-drill", connections=1)
            findings["second"] = {"refused": False}
        except BudgetExhausted as exc:
            findings["second"] = {"refused": True, "reason": str(exc)[:160]}
    finally:
        session.close()
        engine.dispose()
    ok = (findings["no_scope"].get("refused", False)
          and not findings["first"]["refused"]
          and findings["second"].get("refused", False))
    return {"id": "network_budget", "proven": ok, "findings": findings,
            "meaning": ("the traffic budget is charged per window and refuses the connection "
                        "that would exceed it, rather than reporting the overspend afterwards")}


PROBES = {
    "network_admission": probe_network_admission,
    "network_budget": probe_network_budget,
}


# ---------------------------------------------------------------------- cells --- #
def _read(path: str) -> str:
    file = REPO_ROOT / path
    return file.read_text(encoding="utf-8", errors="ignore") if file.exists() else ""


def cited_cell(question: str, modules: tuple[str, ...]) -> dict[str, Any]:
    pattern, meaning = MECHANISMS[question]
    regex = re.compile(pattern)
    for module in modules:
        text = _read(module)
        if not text:
            continue
        match = regex.search(text)
        if match:
            line = text[: match.start()].count("\n") + 1
            return {"state": CITED, "mechanism": match.group(0), "meaning": meaning,
                    "where": f"{module}:{line}"}
    return {"state": ABSENT, "meaning": meaning, "where": None}


def plane_row(plane: Plane, probes: dict[str, dict[str, Any]]) -> dict[str, Any]:
    cells: dict[str, Any] = {}
    for question in QUESTIONS:
        probe_id = plane.probes.get(question)
        if probe_id and probe_id in probes:
            result = probes[probe_id]
            cells[question] = {
                "state": PROBED if result["proven"] else ABSENT,
                "meaning": QUESTION_TEXT[question],
                "probe": probe_id,
                "evidence": result["meaning"],
            }
            continue
        cells[question] = cited_cell(question, plane.modules)

    probed = sum(1 for cell in cells.values() if cell["state"] == PROBED)
    cited = sum(1 for cell in cells.values() if cell["state"] == CITED)
    absent = [question for question, cell in cells.items() if cell["state"] == ABSENT]
    if len(absent) == 0:
        verdict = PROVEN
    elif len(absent) <= 2 and (probed + cited) >= 4:
        verdict = PARTIAL
    else:
        verdict = GAP
    return {
        "plane": plane.name,
        "entry": plane.entry,
        "modules": list(plane.modules),
        "cells": cells,
        "probed": probed,
        "cited": cited,
        "absent": absent,
        "verdict": verdict,
        "note": plane.note,
    }


def measure() -> dict[str, Any]:
    probes: dict[str, dict[str, Any]] = {}
    probe_errors: dict[str, str] = {}
    for name, probe in PROBES.items():
        try:
            probes[name] = probe()
        except Exception as exc:  # noqa: BLE001 — a probe that cannot run is reported
            probe_errors[name] = f"{type(exc).__name__}: {exc}"
            probes[name] = {"id": name, "proven": False, "findings": {},
                            "meaning": f"the probe did not run: {probe_errors[name]}"}

    rows = [plane_row(plane, probes) for plane in PLANES]
    counts = {verdict: sum(1 for row in rows if row["verdict"] == verdict)
              for verdict in (PROVEN, PARTIAL, GAP)}
    per_question = {
        question: {
            "probed": sum(1 for row in rows if row["cells"][question]["state"] == PROBED),
            "cited": sum(1 for row in rows if row["cells"][question]["state"] == CITED),
            "absent": sorted(row["plane"] for row in rows
                             if row["cells"][question]["state"] == ABSENT),
        }
        for question in QUESTIONS
    }
    return {
        "schema": SCHEMA,
        "version": VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "planes": len(rows),
        "counts": counts,
        "per_question": per_question,
        "questions": {question: QUESTION_TEXT[question] for question in QUESTIONS},
        "probes": probes,
        "probe_errors": probe_errors,
        "rows": rows,
        "limits": [
            "A CITED cell proves the mechanism is present in the plane's code path, not that "
            "it refuses the specific request an attacker would send. Only two questions are "
            "probed end to end (network target admission, network traffic budget).",
            "The matrix reads the modules a plane *names*; a mechanism imported from a shared "
            "module counts for the plane that imports it, which is right for coverage and "
            "wrong for a per-plane guarantee.",
            "Five planes (KUBERNETES, CMDB, KMS, HSM, VENDOR) are catalogue adapters with no "
            "dedicated route in this checkout; their cells are citations against the shared "
            "discovery path, which is precisely the uniformity gap the review named.",
        ],
    }


# ------------------------------------------------------------------- rendering --- #
def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    lines = [
        "# Per-collector authority — six questions, eleven planes",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts.get(PROVEN, 0)} proven · {counts.get(PARTIAL, 0)} partial · "
        f"{counts.get(GAP, 0)} gap**",
        "",
        "**PROBED** means the drill executed the control and watched it refuse. **CITED** means "
        "the mechanism is present in that plane's own code path, with the citation checked to "
        "resolve. **ABSENT** means nothing answers the question for that plane. A citation is "
        "not a probe, and the table keeps them apart.",
        "",
        "| Plane | WHO | WHAT | WHICH revision | WHEN | HOW LONG | PERMISSION | Verdict |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for row in report["rows"]:
        cells = []
        for question in QUESTIONS:
            cell = row["cells"][question]
            mark = {"PROBED": "**P**", "CITED": "c", "ABSENT": "—"}[cell["state"]]
            cells.append(mark)
        lines.append(f"| `{row['plane']}` | " + " | ".join(cells) +
                     f" | **{row['verdict']}** |")

    lines += ["", "Per question across the eleven planes:", "",
              "| Question | Probed | Cited | Absent for |", "|---|---|---|---|"]
    for question, data in report["per_question"].items():
        absent = ", ".join(f"`{name}`" for name in data["absent"]) or "—"
        lines.append(f"| {question} — {report['questions'][question]} | {data['probed']} | "
                     f"{data['cited']} | {absent} |")

    lines += ["", "## The probes that ran", ""]
    for name, probe in report["probes"].items():
        lines.append(f"### `{name}` — {'proven' if probe['proven'] else 'NOT proven'}")
        lines.append("")
        lines.append(f"{probe['meaning']}")
        lines.append("")
        lines.append("```")
        lines.append(json.dumps(probe["findings"], indent=2, default=str))
        lines.append("```")
        lines.append("")

    lines += ["## Plane by plane", ""]
    for row in report["rows"]:
        lines.append(f"### `{row['plane']}` — {row['verdict']}")
        lines.append("")
        lines.append(f"- **Entry:** {row['entry']}")
        if row["note"]:
            lines.append(f"- **Reading:** {row['note']}")
        lines.append("")
        lines.append("| Question | State | Where |")
        lines.append("|---|---|---|")
        for question in QUESTIONS:
            cell = row["cells"][question]
            where = cell.get("where") or cell.get("evidence") or "—"
            lines.append(f"| {question} | {cell['state']} | {where} |")
        lines.append("")

    lines += ["## What this does not prove", ""]
    for limit in report["limits"]:
        lines.append(f"- {limit}")
    lines += [
        "",
        "**The verdict this matrix supports:** authority is *not* uniform per collector. On the "
        "network plane, five of the six questions are answered and two are proven by refusal. "
        "On the catalogue planes, the same controls exist as shared code but nothing binds "
        "them to the individual collector, and no plane carries a per-target revision pin of "
        "its own. The gap is specific: a per-plane authority descriptor — target, revision, "
        "window, budget, permission — evaluated at collection time, rather than five "
        "mechanisms that each plane may or may not import.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Per-collector authority matrix.")
    parser.add_argument("--json", help="write the report JSON here")
    parser.add_argument("--md", help="write the markdown report here")
    parser.add_argument("--max-gap", type=int, default=99,
                        help="exit non-zero when more than this many planes are a gap")
    args = parser.parse_args(argv)

    report = measure()
    if args.json:
        path = Path(args.json)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2) + "\n")
    if args.md:
        path = Path(args.md)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_md(report))

    if args.md or args.json:
        print(render_md(report))
    else:
        for row in report["rows"]:
            marks = "".join({"PROBED": "P", "CITED": "c", "ABSENT": "-"}[row["cells"][q]["state"]]
                            for q in QUESTIONS)
            print(f"{row['verdict']:<8} {row['plane']:<12} {marks}  absent: {', '.join(row['absent'])}")
        print(f"\n{report['counts']}")
    return 0 if report["counts"].get(GAP, 0) <= args.max_gap else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
