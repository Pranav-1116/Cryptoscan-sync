"""The single component-construction registry (46, round 38).

The generators are assemblers; this is the pin that they stay that way:
every entry point must produce IDENTICAL component output for the same
input row, because they all construct through one registry. A future
edit that re-introduces per-generator construction fails here first.
"""

from __future__ import annotations

from cbom.component_registry import (
    app_component,
    cbom_crypto_component,
    crypto_layer_component,
    hardware_component,
    vendor_component,
)
from cbom.generator import CbomGenerator
from cbom.technology_bom import materialize_technology_bom


def _crypto_row():
    return {"id": "a1", "algorithm": "RSA-2048", "key_size": 2048,
            "purpose": "ENCRYPTION", "mode": None, "file_path": "src/Keys.java",
            "confidence": "HIGH", "asset": "host-1", "library": "cryptography",
            "first_seen": "2026-09-01T00:00:00Z", "last_seen": None,
            "key_type": None, "location": "src/Keys.java",
            "application": "", "pqc_status": "", "quantum_status": ""}


def test_registry_is_the_single_construction_path():
    # the CBOM generator's crypto component comes from the registry
    via_generator = CbomGenerator()._component(_crypto_row())  # noqa: SLF001 — the pin IS the delegate
    via_registry = cbom_crypto_component(_crypto_row())
    assert via_generator == via_registry

    # and so does the TechBOM crypto layer
    state = materialize_technology_bom({"crypto": [_crypto_row()]})
    layer_row = state["layers"]["cbom"]["components"][0]
    assert layer_row == crypto_layer_component(_crypto_row())
    # both name the same algorithm — one definition, two projections
    assert via_generator["cryptoProperties"]["algorithmProperties"]["algorithm"] \
        == layer_row["algorithm"] == "RSA-2048"
    assert str(via_generator["cryptoProperties"]["algorithmProperties"]
               ["parameterSetIdentifier"]) == str(layer_row["key_size"]) == "2048"


def test_layer_builders_cover_every_kind():
    inventory = {
        "applications": [{"id": "s1", "name": "payment-api", "version": "2",
                          "owner": "team", "environment": "prod",
                          "criticality": "HIGH"}],
        "crypto": [_crypto_row()],
        "hardware": [{"id": "h1", "asset_id": "hsm-1", "manufacturer": "Thales",
                      "model": "Luna", "device_type": "hsm", "hsm": True}],
        "vendors": [{"id": "v1", "name": "Thales", "product": "Luna",
                     "risk_level": "HIGH", "system_ids": ["s1"]}],
    }
    state = materialize_technology_bom(inventory)
    assert state["components_by_layer"] == {"sbom": 1, "cbom": 1,
                                            "hbom": 1, "vendor": 1}
    # and each layer's component is exactly what the registry builds
    assert state["layers"]["sbom"]["components"][0] == app_component(
        inventory["applications"][0])
    assert state["layers"]["hbom"]["components"][0] == hardware_component(
        inventory["hardware"][0])
    assert state["layers"]["vendor"]["components"][0] == vendor_component(
        inventory["vendors"][0])


def test_crypto_component_carries_the_identity_spine():
    """§4.2 round 57: the BOM component carries the same canonical
    asset_key as the crypto_assets row and the fact row — the exported
    document joins back to the write side without inventing identity."""
    row = _crypto_row()
    component = cbom_crypto_component(row)
    props = {p["name"]: p["value"] for p in component["properties"]}
    from shared_models.asset_identity import crypto_asset_key_from_row
    assert props["cryptoscan:asset_key"] == crypto_asset_key_from_row(row)

    # the spine is shape-independent: an evidence row of the SAME crypto
    # fact yields the SAME key on its BOM component
    evidence_shaped = dict(row)
    evidence_shaped.pop("id")
    evidence_shaped["line_number"] = 77  # lines are not identity
    evidence_shaped["content_hash"] = "c" * 64
    assert (cbom_crypto_component(evidence_shaped)["properties"][
        [p["name"] for p in cbom_crypto_component(evidence_shaped)["properties"]].index(
            "cryptoscan:asset_key")]["value"] == props["cryptoscan:asset_key"])


def test_component_without_locator_makes_no_identity_claim():
    component = cbom_crypto_component({"algorithm": "RSA", "key_size": 2048})
    names = [p["name"] for p in (component.get("properties") or [])]
    assert "cryptoscan:asset_key" not in names
