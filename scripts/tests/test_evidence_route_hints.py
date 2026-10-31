"""The routes the product quotes as proof must be routes the product serves.

Three places in this tree answer the question "where can I check that?":

* `shared_models/capability_boundaries.py` — each of the five boundaries carries a
  ``check_at`` route;
* `shared_models/maturity_register.py` — each area carries ``measured_by`` routes;
* `shared_models/enterprise_scenarios.py` — the catalogue carries ``detail_at``.

Those strings are rendered in the console (the maturity and simulation tabs) and
in `docs/CAPABILITY-MATURITY.md`. A stale one is a broken path of the quietest
kind: the reader clicks the evidence and gets a 404, and the sentence that told
them the capability was bounded stops being checkable.

The match is strict — exact, or a parameterised route whose pattern fits. The
lenient ``is_prefix_only`` fallback used for console base constants is deliberately
*not* applied here, because a hint is a specific claim about one route.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import api_contract as contract  # noqa: E402


def _resolves(hint: str) -> bool:
    if not hint.startswith("/"):
        return False
    path = "/api/v1" + hint
    if contract.is_served(path):
        return True
    return any(contract.is_served(candidate) for candidate in contract.candidates(path))


def _hints() -> list[tuple[str, str]]:
    from shared_models import capability_boundaries, enterprise_scenarios, maturity_register

    rows: list[tuple[str, str]] = []
    for statement in capability_boundaries.statements():
        rows.append((f"capability_boundaries:{statement['id']}", statement["check_at"]))
    for area in maturity_register.register()["areas"]:
        for route in area.get("measured_by") or []:
            rows.append((f"maturity_register:{area['id']}", route))
    summary = enterprise_scenarios.summary()
    rows.append(("enterprise_scenarios:summary", summary["detail_at"]))
    return rows


def test_every_quoted_check_route_is_served():
    rows = _hints()
    assert len(rows) >= 8, f"only {len(rows)} route hints found — did a constant get renamed?"
    broken = [(where, hint) for where, hint in rows if not _resolves(hint)]
    assert broken == [], (
        "the product quotes routes as proof that are not served — the console prints them and "
        "the reader gets a 404:\n  " + "\n  ".join(f"{where}: {hint}" for where, hint in broken)
    )


def test_each_hint_points_at_an_operation_an_operator_can_invoke():
    """A 'check at' hint must accept GET or POST.

    Two of the twin's proof routes are ``POST`` by design — ``POST /twin/impact``
    and ``POST /twin/impact-as-of`` take the question in a body, because the asset
    set is the input. The console prints hints as text, not links, so the rule is
    "an operator can call this", not "a browser can open this": a hint that is
    reachable only by DELETE would be a route nobody checks anything with.
    """
    rows = _hints()
    operations = contract.served_operations()
    unusable = []
    for where, hint in rows:
        path = "/api/v1" + hint
        served = path if path in operations else next(
            (candidate for candidate in contract.candidates(path) if candidate in operations), None
        )
        if served is None:
            continue
        if not ({"GET", "POST"} & set(operations[served])):
            unusable.append(f"{where}: {served} accepts {sorted(operations[served])}")
    assert unusable == [], unusable


def test_a_wrong_hint_would_be_caught():
    """Mutation check: the predicate must reject a route nobody serves."""
    assert not _resolves("/estate/evidence/twin/this-route-does-not-exist")
    assert not _resolves("estate/evidence/discovery/maturity")  # missing leading slash
    assert _resolves("/estate/evidence/discovery/maturity")
