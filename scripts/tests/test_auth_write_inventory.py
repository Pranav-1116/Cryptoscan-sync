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
    # 298–301: POST /api/v1/cbom/vbom/{answer,assess,summary,export/cyclonedx} — the VBOM
    # question surface. They are POSTs that write nothing: the question is the body, the answer is
    # read from stored evidence the operator is already entitled to. They cannot carry one
    # require_roles without inventing a role that means "may ask".
    # 302: POST /api/v1/security-controls/snapshots — a collector submits a snapshot. The route
    # refuses a user token outright, so there is no role to require: the credential kind is the
    # gate.
    # 303: POST /api/v1/estate/evidence/twin/artifacts — archives one evidence record the twin
    # already holds into the content-addressed tier. The record is taken from the twin, not from
    # the request body, and the store never overwrites an address, so this adds no content the
    # operator was not already entitled to read. The rest of /api/v1/estate is the same operator
    # surface.
    # 297: POST /api/v1/ops/alerts/alertmanager — guide 117. Alertmanager has no
    # session and no role: the credential is the shared webhook token checked in
    # the handler, because a rule that fires must not be refused with 401.
    # 304: POST /api/v1/estate/evidence/twin/ground-truth — measures the estate against a
    # bank's own declared population and claims. It carries a declaration in the body (up to
    # 5000 claims, far past any query string) and stores none of it: the route returns the
    # measurement and `live_state_modified` is false. It cannot be a GET without inventing a
    # length limit on the bank's own inventory, so it joins the operator surface by method.
    # 305: POST /api/v1/network/crypto-client-offers — a probe or sensor submits observed
    # ClientHello offers, a batch whose whole point is that it is larger than a URL. It stores
    # handshake metadata under the passive path's fail-closed rule and opens no connection of
    # its own; the /api/v1/estate operator surface carries the same reason by prefix.
    # 342: a deliberate regeneration recorded the roadmap computation family
    # (/api/v1/intelligence — 32 writes whose policy is now decided: answers are
    # computed in the caller's tenant context and carry their evidence links) and
    # the CryptoLog surfaces (event ingestion plus the deterministic alert
    # lifecycle). Both families carry their POLICY decisions in
    # `102-authenticated-only-writes.json`; nothing is REVIEW REQUIRED.
    # 345: a deliberate regeneration added the CryptoLog integrity and alert
    # lifecycle writes (POST /integrity/checkpoint, /integrity/verify and
    # /alerts/{id}/transition) under the decided /api/v1/cryptolog family;
    # each carries its policy reason in `102-authenticated-only-writes.json`.
    # 347: a deliberate regeneration added the CryptoLog report family
    # (POST /reports/export and /reports/verify — computation, no store
    # writes, but POSTs under the decided /api/v1/cryptolog policy entry);
    # each carries its policy reason in `102-authenticated-only-writes.json`.
    # 348: a deliberate regeneration added the CryptoLog retention planning
    # POST (a projection computation, recorded under the decided family);
    # each carries its policy reason in `102-authenticated-only-writes.json`.
    # 350: a deliberate regeneration added the ZELNX Performance ingest
    # family (POST /api/v1/performance/ingest and /ingest/batch —
    # docs/performance/01_PRODUCT_SPEC.md Phase 1 collection contracts,
    # idempotent per-metric_id ingestion); each carries its policy reason
    # in `102-authenticated-only-writes.json`.
    # 351: a deliberate regeneration added the ZELNX Performance benchmark
    # write (POST /api/v1/performance/benchmarks — Phase 5 controlled
    # benchmarks, recorded under the decided family); it carries its
    # policy reason in `102-authenticated-only-writes.json`.
    # 352: a deliberate regeneration added the ZELNX Performance metric
    # definitions sync (POST /api/v1/performance/definitions — §5
    # performance_metric_definitions registry, idempotent taxonomy
    # registration under the decided family); it carries its policy
    # reason in `102-authenticated-only-writes.json`.
    assert len(rows) <= 352, (
        f"{len(rows)} authenticated-only writes; the recorded inventory holds 352. "
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
