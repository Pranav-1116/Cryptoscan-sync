"""The maturity register must stay true to the tree it describes.

A register of "what is missing" is only worth anything if it is checked, because
the failure mode is silent: someone lands the missing collector and the register
keeps saying it is absent, or a module is renamed and the reference rots into a
claim about code that is not there.

These tests pin the four properties that make the register evidence:

* every referenced collector module exists in this tree;
* every referenced route is registered in this build;
* every area and surface that is not ``SUBSTANTIAL`` names what is missing — an
  empty missing list is a completeness claim, and only ``SUBSTANTIAL`` may make
  one;
* the six BOM kinds are the six the projection engine actually has, so a new BOM
  cannot be added there and left out of the honesty table;
* nothing outside ``SUBSTANTIAL`` is presented as operational — candidate and
  foundation areas carry the sentence they must not be sold with.

Plus the claims themselves: the overclaims the product must not make are listed
in ``may_not_claim`` and appear nowhere else in the register.
"""

from __future__ import annotations

import inspect
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[4]

sys.path.insert(0, str(ROOT / "shared" / "shared_models"))
sys.path.insert(0, str(ROOT / "services" / "api"))

from shared_models import maturity_register as mr  # noqa: E402


def _register() -> dict:
    return mr.register()


def _all_surfaces() -> list[dict]:
    surfaces: list[dict] = []
    for area in _register()["areas"]:
        surfaces.extend(area["surfaces"])
    return surfaces


def test_every_area_and_surface_declares_a_known_state():
    areas = _register()["areas"]
    assert areas, "the register is empty"
    for area in areas:
        assert area["state"] in mr.STATE_MEANING, area["id"]
        assert area["summary"] and area["claim"], area["id"]
        assert area["surfaces"], f"{area['id']} lists no surfaces"
    for surface in _all_surfaces():
        assert surface["state"] in mr.STATE_MEANING, surface["id"]
        assert surface["note"], surface["id"]


def test_a_partial_surface_must_name_what_is_missing():
    offenders = [
        f"{surface['id']} ({surface['state']})"
        for surface in _all_surfaces()
        if surface["state"] in mr.MUST_LIST_MISSING and not surface["missing"]
    ]
    assert not offenders, (
        "these surfaces are not complete but list nothing left to do, which is a completeness "
        "claim in disguise: " + ", ".join(offenders)
    )
    for area in _register()["areas"]:
        if area["state"] in mr.MUST_LIST_MISSING:
            assert area["missing"], f"{area['id']} is {area['state']} with no missing work listed"


def test_every_referenced_collector_module_exists():
    missing: list[str] = []
    for surface in _all_surfaces():
        collector = surface["collector"]
        if collector is None:
            continue
        path = ROOT / collector
        if not path.exists():
            missing.append(f"{surface['id']}: {collector}")
    assert not missing, "the register points at code that is not in this tree: " + ", ".join(missing)
    # An ABSENT surface must not name a collector: that is how a roadmap entry
    # quietly becomes a capability.
    for surface in _all_surfaces():
        if surface["state"] == mr.ABSENT:
            assert surface["collector"] is None, surface["id"]


def test_every_referenced_route_is_registered_in_this_build():
    from api.routers import collector_depth, estate_graph

    # APIRouter applies its prefix at decoration time, so route.path already
    # carries it — prefixing again would make every route look unregistered.
    registered = set()
    for module in (collector_depth, estate_graph):
        for route in module.router.routes:
            registered.add(getattr(route, "path", ""))

    missing = [route for route in mr.ROUTES if route not in registered]
    assert not missing, "the register advertises routes this build does not serve: " + ", ".join(missing)

    for area in _register()["areas"]:
        for route in area["measured_by"]:
            assert route in mr.ROUTES, f"{area['id']} measures itself by an unlisted route {route}"


def test_the_six_bom_kinds_match_the_projection_engine():
    from api import bom_maturity

    declared = {bom.kind for bom in bom_maturity.BOMS}
    registered = {surface["id"] for surface in mr.BOM_STATES}
    assert registered == declared, (
        "the register and the projection engine disagree about which BOMs exist: "
        f"register={sorted(registered)} engine={sorted(declared)}"
    )


def test_the_overclaims_appear_only_in_the_list_of_things_not_claimed():
    document = _register()
    forbidden = document["claims"]["may_not_claim"]
    assert forbidden
    allowed_text = " ".join(
        [document["claims"]["may_claim"], document["claims"]["why"]]
        + [
            f"{area['summary']} {area['claim']} {surface['note']}"
            for area in document["areas"]
            for surface in area["surfaces"]
        ]
    ).lower()
    for claim in forbidden:
        assert claim.lower() not in allowed_text, (
            f"the register repeats an overclaim in its own material: {claim!r}"
        )


def test_every_claim_that_survives_is_about_this_build():
    """No claim may be about a customer's estate."""
    document = _register()
    text = (document["claims"]["may_claim"] + " " + document["claims"]["why"]).lower()
    assert "any bank environment" not in text
    assert "every cryptographic asset" not in text
    # The permitted claim states its own boundary.
    assert "states per surface where that coverage stops" in text


def test_the_route_serves_the_register_and_requires_authentication():
    from api.routers import collector_depth

    signature = inspect.signature(collector_depth.maturity)
    assert "user" in signature.parameters
    assert signature.parameters["user"].default is not inspect.Parameter.empty
    served = collector_depth.maturity(user="viewer")
    assert served["schema"] == mr.SCHEMA
    assert {area["id"] for area in served["areas"]} == {
        "DIGITAL_TWIN",
        "STATIC_DISCOVERY",
        "RUNTIME_DISCOVERY",
        "NETWORK_DISCOVERY",
        "WINDOWS",
        "HARDWARE_HSM",
        "BOM_PROJECTIONS",
        "SIMULATION_ENGINE",
    }


def test_no_state_is_a_percentage_or_a_score():
    """States, not scores: a number invites rounding up."""
    document = _register()
    for area in document["areas"]:
        assert not re.search(r"\d+\s?%", str(area["state"]))
        assert area["state"].isupper()


def test_operational_words_are_pinned_per_area():
    """A bank may only be told OPERATIONAL where the build cannot beat it."""
    document = _register()
    readiness = {area["id"]: area["readiness"] for area in document["areas"]}
    assert readiness["WINDOWS"] == mr.CANDIDATE_READINESS
    assert readiness["HARDWARE_HSM"] == mr.FOUNDATION_READINESS
    assert readiness["SIMULATION_ENGINE"] == mr.FOUNDATION_READINESS
    for area in document["areas"]:
        if area["readiness"] == mr.OPERATIONAL:
            assert not area["must_not_be_presented_as"]
        else:
            assert area["must_not_be_presented_as"], area["id"]


def test_the_stub_sentences_are_in_the_register():
    """The five capability limits the product must say about itself."""
    document = _register()
    text = repr(document)
    for phrase in (
        "candidate",  # Windows collector
        "not proof of actual",  # HSM operations
        "metadata",  # hardware and runtime
        "generic enterprise simulation",
    ):
        assert phrase in text.lower(), phrase
    simulation = next(a for a in document["areas"] if a["id"] == "SIMULATION_ENGINE")
    assert simulation["state"] == mr.FOUNDATION
    assert any("generic enterprise simulation engine" in s.lower()
               for s in simulation["must_not_be_presented_as"])
