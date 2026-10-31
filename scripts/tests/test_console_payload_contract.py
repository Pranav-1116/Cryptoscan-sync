"""The console's hand-written types must match the payloads the API sends.

The API declares a response model for a small minority of the operations the
console calls; the rest return ``dict``. That does not leave the contract
unchecked — it moves it to ``frontend/src/lib/api.ts``, where a TypeScript
interface is written by hand from the same payload and the page renders
``data.<field>`` against it. When the server stops sending a field, TypeScript is
still happy (the interface is a claim, not a guarantee), the page renders
``undefined``, and nothing fails until someone opens it.

So this test compares the interface with a real payload, for the endpoints whose
answers are computed rather than stored:

* every non-optional field the interface declares must be in the payload;
* every key in the payload must be declared, so the server cannot grow a field
  the console silently ignores;
* for list-valued fields, the element interface is checked against the elements.

Endpoints that need a stored snapshot (the BOM depths, the observed halves of the
runtime/network matrices) are covered by their own tests against a seeded
database; here they are exercised in their no-data shape, which is the shape a
fresh installation actually renders.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "shared" / "shared_models"))
sys.path.insert(0, str(ROOT / "services" / "api"))

import api_contract  # noqa: E402

API_TS = ROOT / "frontend" / "src" / "lib" / "api.ts"


def _types() -> dict[str, dict[str, bool]]:
    return api_contract.ts_interfaces(API_TS)


def _check(payload: dict, interface: str, *, element_of: str | None = None,
           element_interface: str | None = None) -> None:
    types = _types()
    expected = types[interface]
    missing = [field for field, optional in expected.items() if not optional and field not in payload]
    assert missing == [], f"{interface}: the payload does not carry {missing}"
    extra = sorted(set(payload) - set(expected))
    assert extra == [], f"{interface}: the payload carries fields the console does not declare: {extra}"
    if element_of and element_interface:
        rows = payload.get(element_of) or []
        assert rows, f"{element_of} is empty: nothing to check against {element_interface}"
        row = rows[0]
        row_expected = types[element_interface]
        assert [f for f, opt in row_expected.items() if not opt and f not in row] == [], (
            f"{element_interface}: the first row is missing declared fields"
        )
        assert sorted(set(row) - set(row_expected)) == [], (
            f"{element_interface}: row carries undeclared fields"
        )


def test_the_console_types_are_parseable():
    """Guard against the parser silently finding nothing to compare."""
    types = _types()
    assert len(types) >= 100, f"only {len(types)} interfaces parsed from api.ts"
    for required in ("MaturityRegister", "MaturityArea", "EnterpriseSimulationCatalogue",
                     "RuntimeDepth", "NetworkProtocols", "WindowsCollector"):
        assert required in types, required


def test_maturity_register_payload_matches_its_interface():
    from shared_models import maturity_register

    payload = maturity_register.register()
    _check(payload, "MaturityRegister", element_of="areas", element_interface="MaturityArea")
    _check(payload["areas"][0], "MaturityArea")
    surface = payload["areas"][0]["surfaces"][0]
    _check(surface, "MaturitySurface")
    # The five capability boundaries ride on the same payload and are rendered at
    # the top of the register tab; a renamed field here would silently blank the
    # panel, because the page reads doc.boundaries and skips it when absent.
    boundaries = payload["boundaries"]
    assert len(boundaries) == 5
    _check(boundaries[0], "CapabilityBoundary")
    assert boundaries[0]["status"] != "OPERATIONAL"
    assert boundaries[0]["check_at"].startswith("/estate/evidence/")


def test_simulation_catalogue_payload_matches_its_interface():
    from api.routers import estate_graph
    from shared_models import enterprise_scenarios

    payload = estate_graph.estate_twin_simulation_scenarios(user="viewer")
    assert payload["schema"] == enterprise_scenarios.SCHEMA
    _check(payload, "EnterpriseSimulationCatalogue",
           element_of="scenarios", element_interface="EnterpriseSimulationScenario")
    _check(payload["scenarios"][0], "EnterpriseSimulationScenario")


def test_runtime_depth_payload_matches_its_interface():
    from api import runtime_depth

    payload = runtime_depth.registry()
    _check(payload, "RuntimeDepth", element_of="paths", element_interface="RuntimeDepthPath")


def test_network_protocols_payload_matches_its_interface():
    from api import network_protocols

    payload = network_protocols.registry()
    _check(payload, "NetworkProtocols", element_of="protocols", element_interface="NetworkProtocolRow")


def test_windows_collector_payload_matches_its_interface():
    from api import windows_collector

    payload = windows_collector.registry()
    _check(payload, "WindowsCollector", element_of="layers", element_interface="WindowsLayer")


def test_no_console_refuses_to_render_a_missing_required_field():
    """The check itself must fail when a field disappears.

    Mutation test: drop a required key from a real payload and confirm the
    comparison notices. Without this, a parser bug that returns no fields would
    make every test above pass.
    """
    from shared_models import maturity_register

    payload = dict(maturity_register.register())
    payload.pop("claims")
    with pytest.raises(AssertionError) as failure:
        _check(payload, "MaturityRegister")
    assert "claims" in str(failure.value)
