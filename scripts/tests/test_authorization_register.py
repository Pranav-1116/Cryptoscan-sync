"""The authorization register is generated, pinned, and cannot rot in silence.

Guide 100 §5 limit (c): the live sweep proves that every route *enforces what it
declares*; it does not decide *what each route should declare*. That decision was
left as "a policy question per route". `scripts/authorization_register.py` answers
the factual half — for every served operation, which authority guard is actually in
its dependency closure — and `docs/bank-environment/101-authorization-register.md`
is that answer, regenerated on demand.

These tests keep the answer honest:

* the gated counts may only grow and the session-only write count may only shrink,
  so removing a guard from a route is a test failure rather than a quiet diff;
* every DELETE route is either guarded or is one of the six reviewed as
  session-only, so a **new** ungated destructive route cannot be added unnoticed;
* the committed register still matches the application, so the document cannot
  describe a surface that no longer exists.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import authorization_register as ar

REGISTER = Path(__file__).resolve().parents[2] / "docs/bank-environment/101-authorization-register.md"

#: Deletions that are session-only *by review*, not by accident. Each one removes a
#: row from a reference or inventory registry (a graph edge, a schedule, a group
#: entity, an expired vendor profile) — the same authority as the create that made
#: it, which is also session-only. Gating these means deciding a role policy for
#: the whole family, which is a product decision, not a bug fix. Anything that
#: appears here must be named deliberately; a new entry fails the test until it is.
#: `scripts/tests/test_auth_write_inventory.py` is the same fact for *every* method,
#: with the policy reason recorded per prefix.
REVIEWED_SESSION_ONLY_DELETES = frozenset({
    "/api/v1/banking/group/entities/{code}",
    "/api/v1/estate/evidence/schedules/{identifier}",
    "/api/v1/graph/hardware-links/{asset_id}/{hardware_asset_id}",
    "/api/v1/graph/vendor-edges/{parent_vendor_id}/{child_vendor_id}",
    "/api/v1/technology-bom/export-schedules/{schedule_id}",
    "/api/v1/vendors/{vendor_id}/profile",
})

#: Measured when the register was written. Floors may only rise, the write ceiling
#: may only fall: a route that loses its guard trips this.
MIN_ROLE_GATED = 306
MIN_PERMISSION_GATED = 71
# 17: the five tenant-scoped routes of the VBOM/control surface — a question asked of one bank
# entity's evidence is answered inside that entity's tenant role, not by a platform role.
MIN_TENANT_ROLE_GATED = 17
# 303: 298 are the operator surface, 4 are the VBOM POSTs (a question, not a change), 1 is the
# machine-only snapshot intake and 1 archives an evidence record the twin already holds into the
# content-addressed tier. Each is recorded with its reason in
# `102-authenticated-only-writes.json`.
# 338: a deliberate regeneration added the recorded roadmap computation family
# (32 /api/v1/intelligence writes) and the CryptoLog event/alert surfaces; each
# carries its policy reason in `102-authenticated-only-writes.json`.
# 341: a deliberate regeneration added the CryptoLog integrity and alert
# lifecycle writes (checkpoint, verify, per-alert transition); each is recorded
# with its reason in `102-authenticated-only-writes.json`.
# 343: a deliberate regeneration added the CryptoLog report family
# (export + verify — POST computations recorded under the decided family).
# 344: a deliberate regeneration added the CryptoLog retention planning POST
# (a projection computation under the decided family).
# 344 -> 346: a deliberate regeneration added the ZELNX Performance
# ingest family (POST /api/v1/performance/ingest and /ingest/batch,
# docs/performance/01_PRODUCT_SPEC.md Phase 1) — measurements written to
# the caller's tenant context under the decided family policy entry.
# 346 -> 347: a deliberate regeneration added the ZELNX Performance
# benchmark write (POST /api/v1/performance/benchmarks — Phase 5
# controlled benchmark runs recorded under the decided family entry).
# 347 -> 348: a deliberate regeneration added the ZELNX Performance
# metric definitions sync (POST /api/v1/performance/definitions — §5
# registry rows written under the decided family entry).
# 348 -> 349: a deliberate regeneration added the Binary Intelligence
# scan submission (POST /api/v1/binary/scan — artifact identity, scan
# runs, findings and evidence written under the decided family entry).
MAX_SESSION_ONLY_WRITES = 349


@pytest.fixture(scope="module")
def rows() -> list[dict]:
    return ar.register()


def _with_guard(rows: list[dict], kind: str) -> list[dict]:
    return [row for row in rows if kind in row["guards"]]


def test_every_served_operation_is_classified(rows):
    assert len(rows) >= 1200, f"only {len(rows)} operations walked — the route walk is broken"
    for row in rows:
        assert row["method"] in {"GET", "POST", "PUT", "PATCH", "DELETE"}, row
        assert row["path"].startswith("/"), row
        assert row["handler"].count(".") >= 1, row
        assert isinstance(row["guards"], dict), row


def test_the_gated_surface_can_only_grow(rows):
    role = _with_guard(rows, "role")
    permission = _with_guard(rows, "permission")
    tenant_role = _with_guard(rows, "tenant-role")
    assert len(role) >= MIN_ROLE_GATED, (
        f"{len(role)} operations carry a role requirement; this was {MIN_ROLE_GATED}. "
        "A route lost its guard — read the register diff."
    )
    assert len(permission) >= MIN_PERMISSION_GATED, (
        f"{len(permission)} operations carry a permission requirement; this was {MIN_PERMISSION_GATED}"
    )
    assert len(tenant_role) >= MIN_TENANT_ROLE_GATED, (
        f"{len(tenant_role)} operations carry a tenant-role requirement; this was {MIN_TENANT_ROLE_GATED}"
    )


def test_the_session_only_write_surface_can_only_shrink(rows):
    writes = [
        row for row in rows
        if not row["guards"] and row["method"] in ar.WRITE_METHODS
    ]
    assert len(writes) <= MAX_SESSION_ONLY_WRITES, (
        f"{len(writes)} write operations demand nothing beyond a session; this was "
        f"{MAX_SESSION_ONLY_WRITES}. New state-changing routes need a guard or a review entry."
    )


def test_every_destructive_route_is_guarded_or_reviewed(rows):
    """A DELETE with no guard is either a reviewed decision or a defect."""
    ungated = {
        row["path"] for row in rows
        if row["method"] == "DELETE" and not row["guards"]
    }
    unexpected = sorted(ungated - REVIEWED_SESSION_ONLY_DELETES)
    stale = sorted(REVIEWED_SESSION_ONLY_DELETES - ungated)
    assert unexpected == [], (
        "destructive routes open to any signed-in caller that were not reviewed:\\n  "
        + "\n  ".join(unexpected)
    )
    assert stale == [], (
        "reviewed as session-only but now guarded or gone — drop them from the list:\\n  "
        + "\n  ".join(stale)
    )


def test_the_committed_register_matches_the_application(rows):
    """A register that describes a surface nobody can call is worse than none."""
    assert REGISTER.is_file(), f"{REGISTER} is missing; run scripts/authorization_register.py --write"
    text = REGISTER.read_text()
    counts = ar.summary(rows)
    for label, count in counts["by_authority"].items():
        assert re.search(rf"^\| {re.escape(label)} \| {count} \|$", text, re.MULTILINE), (
            f"the register does not record {count} operations demanding `{label}` — "
            "regenerate it: .venv/bin/python scripts/authorization_register.py --write "
            f"{REGISTER.relative_to(REGISTER.parents[2])}"
        )
    assert f"**{counts['operations']}** operations" in text
    assert f"**{counts['session_only_writes']}**" in text
