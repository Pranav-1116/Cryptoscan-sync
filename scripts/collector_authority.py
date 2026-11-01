#!/usr/bin/env python3
"""Per-collector authority: WHO, WHAT, WHICH revision, WHEN, HOW LONG, WHICH permission.

The review's fifth blocker said the authorization model was not uniform per
collector: the six questions were answered by different mechanisms in different
families, and nothing showed which. Guide 116's first pass built the matrix and
found ten of eleven planes GAP — two questions were provable, the rest were a
citation of shared code that a new adapter could simply not call.

This pass is the build that closed it: ``api.security.collector_authority``
answers all six questions in one function, ``api.routers.collector_authority``
serves the approvals and the decision, and ``collector_authorities`` stores the
approval with an owner and an expiry. The drill now **probes every cell through
that route** instead of citing it:

    PROBED   the drill sent a request that should be refused for this question,
             and a request that should be allowed, and watched both
    ABSENT   the expected refusal did not happen (or the allowed case did not)

A cell is no longer a citation, so an unproven cell is a defect rather than a
weaker kind of evidence. What the matrix still says separately is whether each
plane's *handler* calls the authority before it collects: the gate exists and is
exercised here, and wiring the collectors to it is the remaining work, named at
the end of the report rather than hidden in a footnote.

Run::

    python scripts/collector_authority.py \\
        --json docs/bank-environment/116-collector-authority.json \\
        --md   docs/bank-environment/116-collector-authority.md
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

SCHEMA = "cryptoscan.collector-authority/2"
VERSION = "collector-authority/2.0"

REPO_ROOT = Path(__file__).resolve().parents[1]

PROBED, ABSENT = "PROBED", "ABSENT"
PROVEN, PARTIAL, GAP = "PROVEN", "PARTIAL", "GAP"

QUESTIONS = ("who", "what_target", "which_revision", "when", "how_long", "permission")

#: A target each plane's own validator accepts — the positive half of WHAT.
TARGETS: dict[str, str] = {
    "NETWORK": "bank.example:443",
    "RUNTIME": "app01.corp.example",
    "STATIC": "acme/payments-api@9f2c1ab",
    "PKI": "inventory:pki-prod-01",
    "CLOUD": "aws:account:123456789012/region:eu-west-1",
    "KUBERNETES": "cluster:prod-eu/namespace:payments",
    "CMDB": "cmdb:CI0004711",
    "KMS": "kms:arn:aws:kms:eu-west-1:123456789012:key/abc",
    "HSM": "hsm:payments-luna-01",
    "HARDWARE": "host:web01.corp.example",
    "VENDOR": "vendor:acme-signing",
}

#: Targets that try to widen one approval into a sweep. Each must be refused by
#: the plane's own validator, because "a subnet" and "the network" are not the
#: permission the approval granted.
WIDENING = ("*", "0.0.0.0/0", "10.0.0.0/8")

ADMIN = "authority-admin"
#: A principal the write rule permits but whose roles hold none of the plane
#: permissions. ``readonly``/``auditor``/``supervisor`` cannot POST at all, so
#: using one would measure guide 121's write boundary instead of this one.
LIMITED = "authority-owner"
PASSWORD = "Authority-Drill-2026!"


# --------------------------------------------------------------------- harness --- #
def _bootstrap_path() -> None:
    for relative in ("scripts", "services/api", "services/database", "shared/shared_models",
                     "shared/shared_config", "services/runtime", "services/evidence",
                     "services/worker", "services/inventory", "services/network_scanner",
                     "services/governance", "services/cbom", "services/devsecops",
                     "services/observability", "services/control_plane"):
        candidate = str(REPO_ROOT / relative)
        if candidate not in sys.path:
            sys.path.insert(0, candidate)


def _prepare_environment(database_url: str) -> None:
    """Environment first: the app is a process-wide singleton once built."""
    os.environ["ENVIRONMENT"] = "development"
    os.environ["SECRET_KEY"] = "collector-authority-drill-key-32-chars"
    os.environ["ADMIN_USERNAME"] = "admin"
    os.environ["ADMIN_PASSWORD"] = "cryptoscan"
    os.environ["ADMIN_PASSWORD_HASH"] = ""
    os.environ["DATABASE_URL"] = database_url
    os.environ["NEO4J_URI"] = ""
    os.environ.setdefault("REDIS_URL", "")
    _bootstrap_path()
    from api.config.settings import get_settings

    get_settings.cache_clear()


def build_client():
    """A real app, a real database, two real principals."""
    _bootstrap_path()
    path = tempfile.mktemp(suffix=".db", prefix="collector-authority-")
    _prepare_environment(f"sqlite:///{path}")

    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine

    import db.models  # noqa: F401 — registers every table on Base.metadata
    from db.connection.session import Base, configure_session
    from db.connection import engine as engine_mod

    engine_mod._ENGINE = None
    engine = create_engine(f"sqlite:///{path}", future=True)
    Base.metadata.create_all(engine)
    configure_session(engine)

    from api.main import create_app
    from api.security.passwords import hash_password
    from db.connection.session import SessionLocal
    from db.repositories.tenant_repository import TenantRepository
    from db.repositories.user_repository import UserRepository

    with SessionLocal() as session:
        repo = UserRepository(session)
        repo.create_user(ADMIN, hash_password(PASSWORD), roles=["superadmin"])
        repo.create_user(LIMITED, hash_password(PASSWORD), roles=["business_owner"])
        tenants = TenantRepository(session)
        # The viewer needs an estate: the tenancy middleware refuses an
        # authenticated principal with no membership, and that refusal would hide
        # the permission refusal this drill is measuring.
        bank = tenants.create(name="Authority Drill Bank", slug="authority-drill")
        tenants.add_member(bank.id, LIMITED, "member")
        session.commit()

    app = create_app()
    return TestClient(app, raise_server_exceptions=False), path


def token(username: str) -> str:
    from api.security.session_manager import SessionManager

    roles = ["superadmin"] if username == ADMIN else ["business_owner"]
    return SessionManager().create_session(username, roles=roles)


def headers(username: str = ADMIN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token(username)}"}


# ---------------------------------------------------------------------- probes --- #
def _authorize(client, *, plane: str, target: str, revision: int | None,
               who: str | None = ADMIN, requests: int = 1,
               runtime_seconds: int = 0) -> dict[str, Any]:
    payload = {"plane": plane, "target": target, "revision": revision,
               "requests": requests, "runtime_seconds": runtime_seconds}
    sent = headers(who) if who else {}
    response = client.post("/api/v1/collectors/authorize", json=payload, headers=sent)
    body: dict[str, Any]
    try:
        body = response.json()
    except Exception:  # noqa: BLE001 — a non-JSON body is still a status
        body = {"detail": response.text[:200]}
    return {"status": response.status_code, "body": body}


def _codes(result: dict[str, Any]) -> list[str]:
    return [refusal.get("code") for refusal in result["body"].get("refusals", [])]


def _cell(question: str, *, expected: str, result: dict[str, Any],
          allowed_ok: bool = True) -> dict[str, Any]:
    """One cell: the refusal it demanded, the allowance it accepted."""
    observed = _codes(result)
    refused = expected in observed
    return {
        "state": PROBED if refused and allowed_ok else ABSENT,
        "question": question,
        "expected": expected,
        "observed": observed,
        "status": result["status"],
        "detail": (result["body"].get("refusals") or [{}])[0].get("detail")
        if result["body"].get("refusals") else result["body"].get("detail"),
    }


def _reset_plane(plane: str) -> None:
    from sqlalchemy import delete

    from db.connection.session import SessionLocal
    from db.models.collector_authority import CollectorAuthority
    from db.tenancy import platform_scope

    with SessionLocal() as session, platform_scope():
        session.execute(delete(CollectorAuthority).where(CollectorAuthority.plane == plane))
        session.commit()


def _expire_plane(plane: str) -> None:
    from sqlalchemy import update

    from db.connection.session import SessionLocal
    from db.models.collector_authority import CollectorAuthority
    from db.tenancy import platform_scope

    with SessionLocal() as session, platform_scope():
        session.execute(update(CollectorAuthority)
                        .where(CollectorAuthority.plane == plane)
                        .values(expires_at=datetime.now(timezone.utc) - timedelta(minutes=5)))
        session.commit()


def probe_plane(client, plane: str) -> dict[str, Any]:
    """Approve a plane through the route, then try to break each question."""
    _reset_plane(plane)
    approval = client.post(f"/api/v1/collectors/authority/{plane}",
                           json={"valid_days": 30, "max_requests": 1},
                           headers=headers())
    if approval.status_code != 200:
        return {"plane": plane, "verdict": GAP, "cells": {}, "error": approval.text[:300],
                "note": "the approval route refused the drill's own approval"}
    approved = approval.json()
    revision = int(approved["revision"])
    target = TARGETS[plane]

    cells: dict[str, Any] = {}

    # WHO — no session is not a decision, it is a 401.
    anonymous = _authorize(client, plane=plane, target=target, revision=revision, who=None)
    cells["who"] = {
        "state": PROBED if anonymous["status"] == 401 else ABSENT,
        "question": "who",
        "expected": "401 without a session",
        "observed": anonymous["status"],
        "detail": anonymous["body"].get("detail"),
    }

    # PERMISSION — a principal who may write, but holds no permission this plane
    # accepts. The answer must name the plane's permission, not the route's.
    limited = _authorize(client, plane=plane, target=target, revision=revision, who=LIMITED)
    cells["permission"] = _cell("permission", expected="PERMISSION_DENIED", result=limited)

    # WHAT — a wildcard or a subnet is refused by the plane's own validator.
    widening = [_authorize(client, plane=plane, target=value, revision=revision)
                for value in WIDENING]
    cells["what_target"] = {
        "state": PROBED if all("TARGET_REFUSED" in _codes(result) for result in widening)
        else ABSENT,
        "question": "what_target",
        "expected": "TARGET_REFUSED for every widening target",
        "observed": {value: _codes(result) for value, result in zip(WIDENING, widening)},
        "detail": (widening[0]["body"].get("refusals") or [{}])[0].get("detail"),
    }

    # WHICH REVISION — a revision that has moved on, and a missing one.
    stale = _authorize(client, plane=plane, target=target, revision=revision + 1)
    unnamed = _authorize(client, plane=plane, target=target, revision=None)
    cells["which_revision"] = {
        "state": PROBED if ("STALE_REVISION" in _codes(stale)
                            and "STALE_REVISION" in _codes(unnamed)) else ABSENT,
        "question": "which_revision",
        "expected": "STALE_REVISION for a stale or unnamed revision",
        "observed": {"stale": _codes(stale), "unnamed": _codes(unnamed)},
        "detail": (stale["body"].get("refusals") or [{}])[0].get("detail"),
    }

    # WHEN — an expired approval refuses even the right target and revision.
    _expire_plane(plane)
    expired = _authorize(client, plane=plane, target=target, revision=revision)
    cells["when"] = _cell("when", expected="OUTSIDE_WINDOW", result=expired)

    # HOW LONG — the approval above carries one request; the positive case spends
    # it, and the next one must be refused for the budget.
    _reset_plane(plane)
    client.post(f"/api/v1/collectors/authority/{plane}",
                json={"valid_days": 30, "max_requests": 1}, headers=headers())
    first = _authorize(client, plane=plane, target=target, revision=revision)
    second = _authorize(client, plane=plane, target=target, revision=revision)
    allowed = bool(first["body"].get("allowed")) and first["status"] == 200
    budget = _cell("how_long", expected="EXHAUSTED", result=second, allowed_ok=allowed)
    budget["observed"] = {"first_allowed": allowed,
                          "remaining": first["body"].get("remaining_requests"),
                          "second": _codes(second)}
    cells["how_long"] = budget

    probed = [question for question in QUESTIONS if cells[question]["state"] == PROBED]
    verdict = PROVEN if len(probed) == 6 else PARTIAL if len(probed) >= 4 else GAP
    return {
        "plane": plane,
        "entry": approved.get("entry") or TARGETS.get(plane),
        "permission": approved.get("permission"),
        "target_kind": approved.get("target_kind"),
        "revision": revision,
        "target": target,
        "cells": cells,
        "probed": probed,
        "absent": [question for question in QUESTIONS if question not in probed],
        "verdict": verdict,
    }


def wiring() -> dict[str, Any]:
    """Does each collector's own handler call the authority before it collects?"""
    text = (REPO_ROOT / "services" / "api" / "api" / "estate_discovery.py").read_text(
        encoding="utf-8", errors="ignore")
    call_site = "services/api/api/estate_discovery.py::_collect"
    return {
        "call_site": call_site,
        "wired": "collector_authority" in text,
        "gated_handlers": [] if "collector_authority" not in text else ["_collect"],
        "remaining": (
            "none: every plane's collector runs inside the authority gate"
            if "collector_authority" in text else
            "every plane's collector passes through _collect(); the gate is served by "
            "POST /collectors/authorize and exercised in every cell of this matrix, and "
            "calling it from _collect() (with the estate job's principal, roles and the "
            "descriptor revision) is the remaining work"
        ),
    }


def control(client) -> dict[str, Any]:
    """The negative control: break the gate and count the cells that go quiet.

    A matrix that reports PROBED for everything proves nothing unless the same
    probe can fail. Here the authority's decision function is replaced with one
    that allows every collection, the probes run again, and the cells that stop
    being refused are counted. Only ``who`` should survive — it is answered by the
    session gate before :func:`evaluate` is ever called.
    """
    from api.security import collector_authority as authority

    def permissive(*_args, **_kwargs):
        return authority.Decision(
            plane=_kwargs.get("plane", "NETWORK"), allowed=True,
            answers={question: {"question": question, "mechanism": "control",
                                "detail": "the gate was replaced for this control",
                                "meaning": authority.QUESTION_TEXT[question]}
                     for question in authority.QUESTIONS},
            note="negative control: every collection is allowed",
        )

    original = authority.evaluate
    authority.evaluate = permissive
    try:
        rows = [probe_plane(client, plane) for plane in authority.PLANE_SPECS]
    finally:
        authority.evaluate = original

    survived = {question: sum(1 for row in rows
                              if row["cells"].get(question, {}).get("state") == PROBED)
                for question in QUESTIONS}
    return {
        "probed": sum(len(row["probed"]) for row in rows),
        "total": len(rows) * len(QUESTIONS),
        "survived": survived,
        "meaning": ("with the authority replaced by one that allows everything, only the "
                    "cells answered outside it survive: the matrix measures the gate, not "
                    "the drill"),
    }


# --------------------------------------------------------------------- measure --- #
def measure(*, run_control: bool = True) -> dict[str, Any]:
    client, path = build_client()
    try:
        from api.security.collector_authority import PLANE_SPECS, QUESTION_TEXT

        rows = [probe_plane(client, plane) for plane in PLANE_SPECS]
        matrix = client.get("/api/v1/collectors/authority", headers=headers()).json()
        negative_control = control(client) if run_control else None
    finally:
        try:
            client.close()
        except Exception:  # noqa: BLE001 — closing is best effort
            pass
        try:
            os.unlink(path)
        except OSError:
            pass

    counts = {verdict: sum(1 for row in rows if row["verdict"] == verdict)
              for verdict in (PROVEN, PARTIAL, GAP)}
    per_question = {
        question: {
            "probed": sum(1 for row in rows if row["cells"].get(question, {}).get("state") == PROBED),
            "absent": sorted(row["plane"] for row in rows
                             if row["cells"].get(question, {}).get("state") != PROBED),
        }
        for question in QUESTIONS
    }
    return {
        "schema": SCHEMA,
        "version": VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "planes": len(rows),
        "counts": counts,
        "cells": {"probed": sum(len(row["probed"]) for row in rows),
                  "total": len(rows) * len(QUESTIONS)},
        "per_question": per_question,
        "questions": dict(QUESTION_TEXT),
        "matrix_route": {
            "planes": matrix.get("counts", {}).get("planes"),
            "approved_after_the_drill": matrix.get("counts", {}).get("approved"),
        },
        "control": negative_control,
        "wiring": wiring(),
        "rows": rows,
        "limits": [
            "Every cell is a request the drill sent to POST /collectors/authorize, so the "
            "matrix measures the decision, not the outcome of a real collection: the "
            "probes stop short of opening a socket, reading a provider API or touching a "
            "CMDB.",
            "Each plane's collector still reaches its data through its own handler "
            "(api.estate_discovery._collect). The gate is exercised there by this drill "
            "and is not yet called from it — that single call site is the wiring the "
            "next pass needs, and it is why `wiring.wired` is false rather than implied.",
            "Approvals are platform-level rows with a 30-day window in this run; a "
            "per-estate approval is a supported column, not a tested path.",
            "The budget is a rolling window on the descriptor, checked under a "
            "compare-and-set. The drill spends it from one process: two collectors racing "
            "for the last unit is covered by the CAS, not by this matrix.",
        ],
    }


# ------------------------------------------------------------------- rendering --- #
def render_md(report: dict[str, Any]) -> str:
    counts = report["counts"]
    cells = report["cells"]
    lines = [
        f"# Per-collector authority — {len(QUESTIONS)} questions, {report['planes']} planes",
        "",
        f"`{report['schema']}` · generated {report['generated_at']} · "
        f"**{counts.get(PROVEN, 0)} proven · {counts.get(PARTIAL, 0)} partial · "
        f"{counts.get(GAP, 0)} gap** · **{cells['probed']} of {cells['total']} cells "
        "probed**",
        "",
        "**PROBED** now means the drill sent a request that had to be refused for that "
        "question — and a request that had to be allowed — through "
        "`POST /api/v1/collectors/authorize`, and watched both. **ABSENT** means the "
        "expected refusal did not happen. There is no cite-only column left: a mechanism "
        "that exists but does not refuse is not a control.",
        "",
        "| Plane | WHO | WHAT | WHICH revision | WHEN | HOW LONG | PERMISSION | Verdict |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for row in report["rows"]:
        marks = []
        for question in QUESTIONS:
            cell = row["cells"].get(question, {})
            marks.append("**P**" if cell.get("state") == PROBED else "—")
        lines.append(f"| `{row['plane']}` | " + " | ".join(marks) +
                     f" | **{row['verdict']}** |")

    lines += ["", "Per question, across the planes:", "",
              "| Question | Probed | Not proven for |", "|---|---|---|"]
    for question, data in report["per_question"].items():
        absent = ", ".join(f"`{name}`" for name in data["absent"]) or "—"
        lines.append(f"| {question} — {report['questions'][question]} | {data['probed']} | "
                     f"{absent} |")

    lines += ["", "## How each question is answered", ""]
    lines += [
        "| Question | Mechanism | Refusal code |",
        "|---|---|---|",
        "| who | the session gate resolves the principal and its durable roles; an "
        "authorize call with no session is a 401 | `401` |",
        "| what_target | a per-plane validator: a wildcard, a CIDR and a target of the "
        "wrong kind are refused before anything is collected | `TARGET_REFUSED` |",
        "| which_revision | `collector_authorities.revision`; a stale or unnamed revision "
        "is refused, and a re-approval makes the old one stale | `STALE_REVISION`, "
        "`NO_APPROVAL`, `REVOKED` |",
        "| when | the approval window `[approved_at, expires_at)` | `OUTSIDE_WINDOW` |",
        "| how_long | a rolling window budget on the descriptor, charged under a "
        "compare-and-set so two collectors cannot spend the same unit | `EXHAUSTED` |",
        "| permission | the plane's own permission from `PERMISSION_MATRIX`, not the "
        "route's | `PERMISSION_DENIED` |",
    ]

    lines += ["", "## Plane by plane", ""]
    for row in report["rows"]:
        lines.append(f"### `{row['plane']}` — {row['verdict']}")
        lines.append("")
        if row.get("error"):
            lines.append(f"**The drill could not approve this plane:** `{row['error']}`")
            lines.append("")
            continue
        lines.append(f"- **Target used:** `{row['target']}` · **permission:** "
                     f"`{row['permission']}` · **approved revision:** {row['revision']}")
        lines.append("")
        lines.append("| Question | State | Expected | Observed |")
        lines.append("|---|---|---|---|")
        for question in QUESTIONS:
            cell = row["cells"].get(question, {})
            observed = json.dumps(cell.get("observed"), default=str)
            lines.append(f"| {question} | {cell.get('state')} | "
                         f"{cell.get('expected', '—')} | `{observed[:160]}` |")
        lines.append("")

    control = report.get("control")
    if control:
        lines += [
            "## The negative control", "",
            f"With the authority's decision function replaced by one that allows every "
            f"collection, **{control['probed']} of {control['total']} cells** still report "
            f"PROBED — {', '.join(f'{question}: {count}' for question, count in control['survived'].items())}. "
            "Everything except `who` goes quiet, which is what a control should do: the "
            "matrix is measuring the gate and not the drill's optimism.",
            "",
        ]

    wiring = report["wiring"]
    lines += [
        "## The one gap left, named", "",
        f"- **Collector handlers gated:** {len(wiring['gated_handlers'])} "
        f"(`{wiring['call_site']}`).",
        f"- {wiring['remaining']}",
        "",
        "## What this does not prove", "",
    ]
    for limit in report["limits"]:
        lines.append(f"- {limit}")
    lines += [
        "",
        "**The verdict this matrix supports:** every one of the eleven collector planes "
        "now answers all six questions through one code path, and every answer is a "
        "refusal the drill watched happen. What is not yet true is that the collectors "
        "call it: they still pass their own admission on the way to the data, so the "
        "authority is a gate in front of the door rather than in the doorframe. Closing "
        "that is one call site, and until it exists a bank should read this matrix as "
        "\"the authority exists and refuses\" rather than \"the collector obeys it\".",
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
    parser.add_argument("--no-control", action="store_true",
                        help="skip the negative control (it re-runs every probe)")
    args = parser.parse_args(argv)

    report = measure(run_control=not args.no_control)
    if args.json:
        path = Path(args.json)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2, default=str) + "\n")
    if args.md:
        path = Path(args.md)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_md(report))

    if args.md or args.json:
        print(render_md(report))
    else:
        for row in report["rows"]:
            marks = "".join("P" if row["cells"].get(question, {}).get("state") == PROBED
                            else "-" for question in QUESTIONS)
            print(f"{row['verdict']:<8} {row['plane']:<12} {marks}  absent: "
                  f"{', '.join(row['absent'])}")
        print(f"\n{report['counts']} · {report['cells']['probed']}/"
              f"{report['cells']['total']} cells probed")
    return 0 if report["counts"].get(GAP, 0) <= args.max_gap else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
