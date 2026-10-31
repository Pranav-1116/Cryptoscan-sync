"""The five sentences the product owes a bank, and the areas they belong to.

This file checks a property that prose cannot hold on its own: that the boundary
statements are *the same* statements the maturity register and the capability
record publish. A boundary that exists only in a doc is a marketing claim with a
footnote; one that is asserted here, rendered in the console and pointed at a
route that can be called is a product statement.

It also pins the five capabilities, because the list is the deliverable: dropping
a row silently is exactly the failure this module prevents.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[4]

sys.path.insert(0, str(ROOT / "shared" / "shared_models"))

from shared_models import capability_boundaries as cb  # noqa: E402
from shared_models import maturity_register as mr  # noqa: E402


def test_the_five_capabilities_are_the_five_that_may_not_be_sold_as_operational():
    assert [row["id"] for row in cb.STATEMENTS] == [
        "WINDOWS_COLLECTOR",
        "HARDWARE_DISCOVERY",
        "HSM_OPERATIONS",
        "RUNTIME_INVOCATION",
        "SIMULATION_ENGINE",
    ]


def test_no_boundary_is_presented_as_operational():
    for row in cb.STATEMENTS:
        assert row["status"] in {"CANDIDATE", "FOUNDATION"}, row["id"]
        assert row["status"] != mr.OPERATIONAL
        # Both halves are required: what is real, and what is not.
        assert row["what_is_real"].strip(), row["id"]
        assert row["not_operational"].strip(), row["id"]
        assert "not " in row["says"].lower(), row["id"]


def test_each_boundary_names_a_register_area_that_is_not_operational():
    areas = {area["id"]: area for area in mr.register()["areas"]}
    for row in cb.STATEMENTS:
        assert row["area"] in areas, row["id"]
        assert areas[row["area"]]["readiness"] != mr.OPERATIONAL, row["id"]


def test_every_area_that_is_not_operational_states_its_own_limit():
    """A gap in the register without a sentence is a gap a sales deck can fill.

    The five published boundaries cover the capabilities a bank asks about by
    name. The remaining partial areas carry the same obligation in the register
    itself, so no non-operational area is left without a sentence."""
    covered = {row["area"] for row in cb.STATEMENTS}
    for area in mr.register()["areas"]:
        if area["readiness"] == mr.OPERATIONAL:
            continue
        assert area["id"] in covered or area["must_not_be_presented_as"], area["id"]


def test_the_register_publishes_the_same_boundary_statements():
    assert mr.register()["boundaries"] == cb.statements()


def test_each_boundary_points_at_a_route_the_register_already_measures():
    """A reader must be able to check the claim, not just read it."""
    routes = set(mr.register()["routes"])
    for row in cb.STATEMENTS:
        assert row["check_at"] in routes, f"{row['id']} points at {row['check_at']}"


def test_the_boundary_texts_do_not_soften_into_a_completeness_claim():
    text = " ".join(row["says"] for row in cb.STATEMENTS).lower()
    for overclaim in (
        "every cryptographic asset",
        "any bank environment",
        "production windows collector,",
    ):
        assert overclaim not in text, overclaim
    # the simulation row must not claim the generic engine in the affirmative
    simulation = next(r for r in cb.STATEMENTS if r["id"] == "SIMULATION_ENGINE")
    assert "not fully implemented" in simulation["says"]
    assert "generic enterprise engine" in simulation["says"]


def test_the_boundary_list_is_copied_not_shared():
    cb.statements()[0]["says"] = "everything is operational"
    assert cb.STATEMENTS[0]["says"] != "everything is operational"
