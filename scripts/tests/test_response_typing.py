"""The untyped-response list is a ratchet, not a shrug.

Guide 100 §5 (a) counts the operations that declare no response model. The count
alone is easy to read past, and a new route arriving with no model kept it growing
without anyone deciding to. `scripts/response_typing.py` records the exact list;
these tests make it binding:

* the application's untyped set must equal the recorded one, so a **new** untyped
  route fails the build until it is written down — the regeneration is the
  decision and shows up as a diff;
* the recorded list may not grow: typing routes shrinks it, and the shrink is the
  only way the file changes legitimately;
* the typed count keeps a floor, so a model that is removed (rather than replaced)
  fails instead of quietly widening the gap.
"""

from __future__ import annotations

import pytest

import response_typing

#: Measured when the inventory was written (99 of 1255 typed). Grows only.
MIN_TYPED_OPERATIONS = 99


@pytest.fixture(scope="module")
def untyped() -> list[str]:
    return response_typing.untyped()


@pytest.fixture(scope="module")
def recorded() -> list[str]:
    return response_typing.load()


def test_the_inventory_is_present_and_parseable(recorded):
    assert recorded, (
        f"{response_typing.INVENTORY} is missing or empty — run "
        "`.venv/bin/python scripts/response_typing.py --write`"
    )


def test_the_typed_surface_can_only_grow():
    typed = response_typing.typed()
    assert len(typed) >= MIN_TYPED_OPERATIONS, (
        f"{len(typed)} operations declare a response schema; this was {MIN_TYPED_OPERATIONS}. "
        "A response model was removed — a page that read that field now reads `undefined`."
    )


def test_every_untyped_operation_is_recorded(untyped, recorded):
    unrecorded = sorted(set(untyped) - set(recorded))
    assert unrecorded == [], (
        "operations that declare no response model but are not in the inventory "
        "(a new route chose `dict` by default):\n  "
        + "\n  ".join(unrecorded)
        + "\n\nAdd a `response_model=` to the route, or record the decision with "
        "`.venv/bin/python scripts/response_typing.py --write`."
    )


def test_the_inventory_does_not_claim_routes_that_are_now_typed(untyped, recorded):
    """A typed route left in the inventory inflates the gap the audit reports."""
    stale = sorted(set(recorded) - set(untyped))
    assert stale == [], (
        "operations recorded as untyped that now declare a response schema — "
        "regenerate the inventory and read the diff:\n  " + "\n  ".join(stale)
    )


#: 1157: GET /api/v1/security-controls/export. Deliberately untyped and recorded rather than
#: typed: the CycloneDX branch returns a document whose shape is owned by the CycloneDX 1.6 schema
#: (validated by `cbom.cyclonedx16`) and the CEF branch returns `text/plain` lines. A
#: `response_model` here would publish an `application/json` contract for a route that returns
#: SIEM lines, which is worse than an honest gap.
#: 1158: POST /api/v1/network/crypto-client-offers. ClientHello offer ingest, shape-owned by the
#: network-evidence record schema (cryptoscan.network-evidence/1) shared with the rest of the
#: observation-intake family (crypto-observe, crypto-passive), which is recorded untyped for the
#: same reason: the records are validated by their builders, not by a response model.
#: 1159: POST /api/v1/cryptolog/reports/export. The auditor pack: a ZIP whose manifest
#: hashes every file, verified with any sha256sum-style check. A `response_model` here would
#: publish an application/json contract for an archive, which is worse than an honest gap —
#: recorded deliberately, like the export family above. The typed
#: POST /api/v1/cryptolog/reports/verify carries the examiner verdict as JSON.
MAX_UNTYPED_OPERATIONS = 1159


def test_the_untyped_surface_does_not_grow(untyped, recorded):
    assert len(untyped) == len(recorded)
    assert len(untyped) <= MAX_UNTYPED_OPERATIONS, (
        f"{len(untyped)} operations declare no response model; the ceiling is "
        f"{MAX_UNTYPED_OPERATIONS}. This may only go down."
    )
