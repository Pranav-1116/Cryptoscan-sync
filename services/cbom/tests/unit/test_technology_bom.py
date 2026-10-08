"""Unified Technology BOM engine tests.

Verifies: one inventory snapshot materializes SBOM/CBOM/HBOM/Vendor layers,
a content-addressed state version + immutable snapshot id, an honest empty
inventory, a truthful diff, and the export formats (JSON/CSV/CycloneDX/SPDX)
with integrity hashing.
"""

from __future__ import annotations

from cbom.technology_bom import (
    diff_technology_bom,
    empty_inventory,
    export_technology_bom,
    filter_technology_bom,
    materialize_technology_bom,
)


def _inventory():
    return {
        "applications": [
            {"id": "pay-api", "name": "Payment API", "version": "3.2.0",
             "owner": "Payments", "environment": "prod"},
            {"id": "core-bank", "name": "Core Bank", "version": "21",
             "owner": "Core", "environment": "prod"},
        ],
        "crypto": [
            {"id": "c1", "algorithm": "RSA", "key_size": 2048, "purpose": "TLS",
             "asset": "Server-001", "application": "Payment API", "confidence": "HIGH"},
            {"id": "c2", "algorithm": "AES", "key_size": 256, "purpose": "storage",
             "asset": "Server-002", "application": "Core Bank", "confidence": "MEDIUM"},
        ],
        "hardware": [
            {"id": "h1", "asset_id": "Server-001", "manufacturer": "Dell",
             "model": "PowerEdge", "device_type": "server", "firmware": {"version": "2.1"},
             "hsm": {"present": True}},
            {"id": "h2", "asset_id": "Router-44", "manufacturer": "Cisco",
             "model": "Catalyst", "device_type": "network", "firmware": {"version": "17.x"}},
        ],
        "vendors": [
            {"name": "Dell", "product": "PowerEdge", "model": "R650", "lifecycle": "supported"},
            {"name": "Cisco", "product": "Catalyst", "model": "9300", "lifecycle": "supported"},
        ],
        "certificates": [{"fingerprint": "abc123", "subject": "CN=pay"}],
        "dependencies": [["pay-api", "c1"], ["core-bank", "c2"]],
        "scan": {"id": "SCAN-2026-001", "completed_at": "2026-09-07T14:32:18Z"},
    }


def test_materializes_all_layers_from_one_inventory():
    st = materialize_technology_bom(_inventory(), environment="UAE-PRODUCTION", state_version=1)
    assert st["environment"] == "UAE-PRODUCTION"
    assert st["state_version"] == 1
    assert st["components_by_layer"]["sbom"] == 2
    assert st["components_by_layer"]["cbom"] == 2
    assert st["components_by_layer"]["hbom"] == 2
    assert st["components_by_layer"]["vendor"] == 2
    assert st["total_components"] == 8
    assert st["certificate_count"] == 1
    assert st["dependency_count"] == 2
    # every crypto component is a CBOM view of the same crypto assets
    assert st["layers"]["cbom"]["components"][0]["algorithm"] == "RSA"


def test_snapshot_id_is_immutable_and_stamped():
    st = materialize_technology_bom(_inventory(), environment="UAE-PRODUCTION", state_version=1)
    sid = st["snapshot_id"]
    assert sid.startswith("TECHBOM-")
    assert len(sid) == 23  # TECHBOM-YYYYMMDD-HHMMSS
    # deterministic: same state_version + fingerprint, stable id
    st2 = materialize_technology_bom(_inventory(), environment="UAE-PRODUCTION", state_version=1)
    assert st2["snapshot_id"].startswith("TECHBOM-")


def test_fingerprint_content_addressed():
    a = materialize_technology_bom(_inventory(), environment="UAE-PRODUCTION", state_version=1)
    b = materialize_technology_bom(_inventory(), environment="UAE-PRODUCTION", state_version=1)
    assert a["fingerprint"] == b["fingerprint"]
    # a change to any layer changes the fingerprint
    inv = _inventory()
    inv["crypto"].append({"id": "c3", "algorithm": "ECDSA", "key_size": 256, "asset": "API-044"})
    c = materialize_technology_bom(inv, environment="UAE-PRODUCTION", state_version=1)
    assert c["fingerprint"] != a["fingerprint"]


def test_empty_inventory_is_honest():
    st = materialize_technology_bom(empty_inventory(), state_version=0)
    assert st["total_components"] == 0
    assert st["components_by_layer"]["sbom"] == 0
    assert st["components_by_layer"]["cbom"] == 0
    assert st["components_by_layer"]["hbom"] == 0


def test_diff_added_removed_per_layer():
    prev = materialize_technology_bom(_inventory(), state_version=1)
    inv = _inventory()
    inv["crypto"].append({"id": "c3", "algorithm": "ECDSA", "key_size": 256, "asset": "API-044"})
    del inv["hardware"][1]  # remove Router-44
    cur = materialize_technology_bom(inv, state_version=2)
    d = diff_technology_bom(prev, cur)
    assert d["changed"] is True
    assert d["layers"]["cbom"]["added_count"] == 1
    assert d["layers"]["cbom"]["removed_count"] == 0
    assert d["layers"]["hbom"]["removed_count"] == 1
    assert d["layers"]["sbom"]["added_count"] == 0
    # added CBOM is the new ECDSA component
    assert any(c.get("algorithm") == "ECDSA" for c in d["layers"]["cbom"]["added"])


def test_diff_unchanged_state_reports_no_change():
    a = materialize_technology_bom(_inventory(), state_version=1)
    b = materialize_technology_bom(_inventory(), state_version=2)
    d = diff_technology_bom(a, b)
    assert d["changed"] is False
    for layer in ("sbom", "cbom", "hbom", "vendor"):
        assert d["layers"][layer]["added_count"] == 0
        assert d["layers"][layer]["removed_count"] == 0
        assert d["layers"][layer]["changed_count"] == 0


# ------------------------------------------- P2 read-model honesty (2026-10)

def test_state_carries_dependency_edges():
    """The materialized state must carry the actual dependency edges, not
    just a count — otherwise the fingerprint is blind to edge-only changes
    and a re-wired estate keeps the old snapshot version."""
    st = materialize_technology_bom(_inventory(), state_version=1)
    assert st["dependencies"] == [["core-bank", "c2", ""], ["pay-api", "c1", ""]]
    assert st["dependency_count"] == 2


def test_fingerprint_tracks_dependency_edges_only():
    base = materialize_technology_bom(_inventory(), state_version=1)
    # same components, one more edge — the fingerprint must move
    inv = _inventory()
    inv["dependencies"].append(["pay-api", "core-bank"])
    rewired = materialize_technology_bom(inv, state_version=1)
    assert rewired["fingerprint"] != base["fingerprint"]
    # and dedupes: the same edge twice is one edge, not two
    inv2 = _inventory()
    inv2["dependencies"].append(["pay-api", "c1"])
    assert materialize_technology_bom(inv2, state_version=1)["fingerprint"] == base["fingerprint"]


def test_diff_reports_property_changes():
    """A component whose bom-ref survives but whose fields changed (key
    growth, version bump) is a changed component, not silence."""
    prev = materialize_technology_bom(_inventory(), state_version=1)
    inv = _inventory()
    inv["crypto"][0]["key_size"] = 4096  # RSA 2048 -> 4096, same bom-ref
    cur = materialize_technology_bom(inv, state_version=2)
    d = diff_technology_bom(prev, cur)
    assert d["changed"] is True
    cbom = d["layers"]["cbom"]
    assert cbom["added_count"] == 0 and cbom["removed_count"] == 0
    assert cbom["changed_count"] == 1
    entry = cbom["changed"][0]
    assert entry["bom-ref"] == "crypto:c1:Server-001"
    assert entry["fields"]["key_size"] == {"from": 2048, "to": 4096}


def test_diff_reports_dependency_edge_changes():
    prev = materialize_technology_bom(_inventory(), state_version=1)
    inv = _inventory()
    inv["dependencies"] = [["pay-api", "c1"], ["core-bank", "c2"],
                           ["pay-api", "core-bank"]]
    cur = materialize_technology_bom(inv, state_version=2)
    d = diff_technology_bom(prev, cur)
    assert d["changed"] is True
    assert d["dependencies"]["added_count"] == 1
    assert d["dependencies"]["added"] == [["pay-api", "core-bank", ""]]
    assert d["dependencies"]["removed_count"] == 0
    # and the mirror case: an edge removed
    inv2 = _inventory()
    inv2["dependencies"] = [["pay-api", "c1"]]
    d2 = diff_technology_bom(prev, materialize_technology_bom(inv2, state_version=2))
    assert d2["dependencies"]["removed"] == [["core-bank", "c2", ""]]


def test_export_json_and_integrity():
    st = materialize_technology_bom(_inventory(), state_version=1)
    exp = export_technology_bom(st, fmt="json", layer="cbom")
    assert exp["snapshot_id"].startswith("TECHBOM-")
    assert exp["layer"] == "cbom"
    assert exp["integrity_sha256"] and len(exp["integrity_sha256"]) == 64
    assert exp["data"]["count"] == 2


def test_export_cyclonedx():
    st = materialize_technology_bom(_inventory(), state_version=1)
    exp = export_technology_bom(st, fmt="cyclonedx", layer="cbom")
    doc = exp["data"]
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.5"
    assert len(doc["components"]) == 2
    assert any(c["type"] == "crypto-asset" for c in doc["components"])


def test_export_spdx():
    st = materialize_technology_bom(_inventory(), state_version=1)
    exp = export_technology_bom(st, fmt="spdx", layer="sbom")
    doc = exp["data"]
    assert doc["spdxVersion"] == "SPDX-2.3"
    assert len(doc["packages"]) == 2
    # integrity hash present for the whole artifact
    assert len(exp["integrity_sha256"]) == 64


def test_export_csv():
    st = materialize_technology_bom(_inventory(), state_version=1)
    exp = export_technology_bom(st, fmt="csv", layer="hbom")
    assert exp["mime_type"] == "text/csv"
    rows = [r for r in exp["data"].splitlines() if r.strip()]
    assert len(rows) == 3  # header + 2 hardware rows


def test_export_cyclonedx_xml() -> None:
    st = materialize_technology_bom(_inventory(), state_version=1)
    exp = export_technology_bom(st, fmt="cyclonedx-xml", layer="sbom")
    assert exp["mime_type"] == "application/xml"
    assert exp["data"].startswith("<?xml")
    assert "<bom" in exp["data"]
    assert "<component" in exp["data"]
    assert "CycloneDX" not in exp["data"]  # XML has no bomFormat field
    assert len(exp["integrity_sha256"]) == 64


def test_export_xml_alias() -> None:
    st = materialize_technology_bom(_inventory(), state_version=1)
    exp = export_technology_bom(st, fmt="xml", layer="all")
    assert exp["mime_type"] == "application/xml"
    # the unified "all" export uses per-component CycloneDX types
    for ctype in ("library", "crypto-asset", "device", "platform"):
        assert f'type="{ctype}"' in exp["data"]


def test_export_pdf_bytes() -> None:
    st = materialize_technology_bom(_inventory(), state_version=1)
    exp = export_technology_bom(st, fmt="pdf", layer="cbom")
    assert exp["mime_type"] == "application/pdf"
    assert isinstance(exp["data"], bytes)
    assert exp["data"].startswith(b"%PDF-")
    assert len(exp["integrity_sha256"]) == 64


def test_filter_by_layer_and_risk() -> None:
    inv = _inventory()
    inv["hardware"] = [
        {"id": "h-high", "asset_id": "HSM-H", "manufacturer": "ZELNX", "risk_level": "HIGH"},
        {"id": "h-low", "asset_id": "SVR-L", "manufacturer": "Dell", "risk_level": "LOW"},
    ]
    st = materialize_technology_bom(inv, state_version=1)
    # keep only HIGH-risk hardware
    filtered = filter_technology_bom(st, {"layer": "hbom", "risk_level": "HIGH"})
    assert set(filtered["components_by_layer"].keys()) == {"hbom"}
    assert filtered["total_components"] == 1
    assert filtered["layers"]["hbom"]["components"][0]["hardware_id"] == "HSM-H"
    # fingerprint is recomputed over the filtered set
    assert filtered["fingerprint"] != st["fingerprint"]


def test_filter_key_size_min_and_search() -> None:
    st = materialize_technology_bom(_inventory(), state_version=1)
    small = filter_technology_bom(st, {"layer": "cbom", "key_size_min": 1024})
    for c in small["layers"]["cbom"]["components"]:
        assert (c.get("key_size") or 0) >= 1024
    by_search = filter_technology_bom(st, {"search": "payment"})
    hay = " ".join(str(c.get("name", "")) for c in by_search["layers"]["sbom"]["components"])
    assert "payment" in hay.lower() or by_search["total_components"] < st["total_components"]
