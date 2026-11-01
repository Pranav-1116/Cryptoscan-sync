"""No write route may choose "no role" silently.

Guide 100 §5 (c) ends on an honest limit: the sweep proves each route enforces
what it declares, and says nothing about whether it should have declared a role.
1212 operations sit behind the session gate; most are deliberately authenticated-
only, but that decision lived only in the head of whoever wrote the route.

`scripts/auth_write_inventory.py` records the decision: every write that is neither
public nor role-gated, with the policy reason for its prefix. These tests make the
record binding:

* the application's set of authenticated-only writes must **equal** the inventory,
  so a new one is a build failure until someone regenerates the inventory — the
  regeneration *is* the decision, and it shows up in review as a diff;
* every entry must carry a reason, and no reason may be "REVIEW REQUIRED";
* the inventory may only shrink without a deliberate regeneration;
* role-gated write count may only grow (removing a guard fails).
"""

from __future__ import annotations

import pytest

import auth_write_inventory as inventory

MIN_ROLE_GATED_WRITES = 280


@pytest.fixture(scope="module")
def rows() -> list[dict]:
    return inventory.inventory()


@pytest.fixture(scope="module")
def recorded() -> dict[str, str]:
    return inventory.load()


def test_the_inventory_is_present_and_parseable(recorded):
    assert recorded, (
        f"{inventory.INVENTORY} is missing or empty — run "
        "`.venv/bin/python scripts/auth_write_inventory.py --write`"
    )


def test_every_authenticated_only_write_is_recorded(rows, recorded):
    """A route that appears is a decision nobody made."""
    live = {inventory._key(row) for row in rows}
    unrecorded = sorted(live - set(recorded))
    assert unrecorded == [], (
        "write operations with no role requirement that nobody recorded a policy for:\n  "
        + "\n  ".join(unrecorded)
        + "\n\nEither give the route a role requirement, or state the reason in "
        "`POLICY` in scripts/auth_write_inventory.py and run it with `--write`."
    )


def test_no_recorded_write_has_disappeared_without_a_regeneration(rows, recorded):
    """An entry that vanishes means a guard was added *or* the route was removed."""
    live = {inventory._key(row) for row in rows}
    stale = sorted(set(recorded) - live)
    assert stale == [], (
        "operations recorded as authenticated-only that the application no longer serves "
        "in that shape — regenerate the inventory and read the diff:\n  " + "\n  ".join(stale)
    )


def test_every_recorded_reason_is_a_decision(rows):
    undecided = sorted(
        inventory._key(row) for row in rows if row["reason"] in ("", "REVIEW REQUIRED")
    )
    assert undecided == [], (
        "write operations whose policy is still undecided (no `POLICY` prefix matches them):\n  "
        + "\n  ".join(undecided)
    )


def test_the_authenticated_only_write_surface_is_pinned(rows, recorded):
    """The number itself, so a shrink is noticed even when the diff looks fine."""
    assert len(rows) == len(recorded)
    # 295: the generic simulation engine's run endpoint (POST, computes over stored
    # evidence and writes nothing) joins the operator surface under /api/v1/estate.
    # 296: POST /api/v1/collectors/authorize — guide 116. It cannot carry one
    # require_roles: each collector plane has its own permission, and the route
    # exists to ask "may this plane be collected" for whichever one is named. The
    # principal comes from the session gate; the plane's permission is checked in
    # api.security.collector_authority.evaluate() against PERMISSION_MATRIX.
    assert len(rows) <= 296, (
        f"{len(rows)} authenticated-only writes; the recorded inventory holds 347. "
        "This count may only go down (a route gained a role) without a regeneration."
    )


def test_the_role_gated_write_surface_can_only_grow(rows):
    """Removing a guard from a gated write has to fail here, not in production."""
    import api_contract

    gated = inventory.role_gated_operations()
    writes = {
        (method.upper(), path)
        for path, methods in api_contract.served_operations().items()
        if not inventory.is_public(path)
        for method in methods
        if method.upper() in inventory.WRITE_METHODS
    }
    gated_writes = [item for item in writes if item in gated]
    assert len(gated_writes) >= MIN_ROLE_GATED_WRITES, (
        f"{len(gated_writes)} write operations require a role; this was "
        f"{MIN_ROLE_GATED_WRITES}. A guard was removed — read the route diff."
    )
    assert len(gated_writes) + len(rows) == len(writes), (
        "every write is either role-gated or recorded as authenticated-only; the two sets "
        "no longer partition the write surface"
    )
