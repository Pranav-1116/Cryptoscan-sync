"""BOM downloads: a projection rendered twice is the same document, limits included."""
from __future__ import annotations

import json

import pytest

from shared_models import bom_export
from shared_models.estate_graph import build_graph

PAYLOAD = {
    "estate": "payments",
    "scope": "production",
    "assets": [
        {"ref": "api", "type": "APPLICATION", "name": "payments-api", "owner": "Payments"},
        {"ref": "host", "type": "HOST", "name": "host-01", "identity": {"hostname": "host-01"}},
        {"ref": "ossl", "type": "LIBRARY", "name": "OpenSSL", "identity": {"name": "OpenSSL", "version": "3.0.13"}},
        {
            "ref": "lb",
            "type": "LOAD_BALANCER",
            "name": "payments-lb",
            "identity": {"name": "payments-lb", "version": "12.1"},
        },
    ],
    "evidence": [
        {
            "evidence_id": "ev-host",
            "source": "linux-static",
            "evidence_type": "STATIC_OBSERVED",
            "target": "host",
            "layer": "PLATFORM",
            "facts": {"hostname": "host-01"},
        },
        {
            "source": "linux-static",
            "evidence_type": "STATIC_OBSERVED",
            "target": "ossl",
            "layer": "APPLICATION",
            "facts": {"algorithm": "AES", "key_size": 256, "mode": "GCM"},
        },
        {
            "source": "network-tls",
            "evidence_type": "NETWORK_ACTIVE_OBSERVED",
            "target": "lb",
            "layer": "NETWORK_TRANSPORT",
            "facts": {"protocol": "TLS", "version": "1.3"},
        },
    ],
    "relationships": [
        {
            "subject": "api",
            "predicate": "runs_on",
            "object": "host",
            "basis": "DEPLOYMENT_CONFIG",
            "evidence_ids": ["ev-host"],
        }
    ],
    "collectors": [{"plane": "Linux hosts", "state": "COMPLETE", "expected": 1, "collected": 1}],
    "coverage": [{"plane": "Linux hosts", "expected": 1, "collected": 1}],
}


@pytest.fixture
def graph():
    return build_graph(PAYLOAD)


def test_a_cbom_download_is_a_cyclonedx_document_carrying_its_provenance(graph):
    document = bom_export.to_document(graph.project("CBOM"), "cyclonedx")

    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.6"
    assert document["serialNumber"].startswith("urn:uuid:")
    names = {property_row["name"] for property_row in document["metadata"]["properties"]}
    assert "cryptoscan:projection_id" in names
    assert "cryptoscan:not_authoritative" in names
    assert "cryptoscan:boundary" in names
    crypto = [component for component in document["components"] if component["type"] == "cryptographic-asset"]
    assert crypto, "a CBOM download with no cryptographic component is not a CBOM"
    assert crypto[0]["cryptoProperties"]["assetType"] in {"algorithm", "protocol"}
    assert any(p["name"] == "cryptoscan:evidence_id" for p in crypto[0]["properties"])


def test_the_same_projection_renders_the_same_document(graph):
    projection = graph.project("TECHBOM")

    first = bom_export.to_document(projection, "cyclonedx")
    second = bom_export.to_document(projection, "cyclonedx")

    assert first == second
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_two_projections_of_different_evidence_get_different_serial_numbers(graph):
    renamed = [dict(asset) for asset in PAYLOAD["assets"]]
    renamed[0]["name"] = "payments-api-v2"
    other = build_graph({**PAYLOAD, "assets": renamed})

    first = bom_export.to_document(graph.project("TECHBOM"), "cyclonedx")
    second = bom_export.to_document(other.project("TECHBOM"), "cyclonedx")

    assert first["serialNumber"] != second["serialNumber"]


def test_an_edge_with_one_end_outside_the_projection_is_not_invented(graph):
    document = bom_export.to_document(graph.project("SBOM"), "cyclonedx")

    # the library is in the SBOM, the host it might depend on is not: CycloneDX has no way to
    # say "UNKNOWN endpoint", so no dependency is written rather than a dangling ref
    refs = {component["bom-ref"] for component in document["components"]}
    for dependency in document["dependencies"]:
        assert dependency["ref"] in refs
        assert all(target in refs for target in dependency["dependsOn"])


def test_the_native_format_is_the_projection_without_improvement(graph):
    projection = graph.project("HBOM")
    document = bom_export.to_document(projection, "json")

    assert document["format"] == "json"
    assert document["projection"] == projection
    assert document["not_authoritative"]
    assert document["limits"] == bom_export.LIMITS


def test_the_filename_names_the_kind_and_the_projection(graph):
    projection = graph.project("NBOM")
    name = bom_export.filename(projection, "cyclonedx")

    assert name.startswith("cryptoscan-nbom-")
    assert name.endswith(".cdx.json")
    assert str(projection["projection_id"])[:12] in name


def test_an_unknown_format_is_refused_not_guessed(graph):
    with pytest.raises(ValueError):
        bom_export.to_document(graph.project("SBOM"), "pdf")


def test_exporting_a_projection_without_an_id_is_refused():
    with pytest.raises(ValueError):
        bom_export.to_cyclonedx({"bom": "SBOM", "components": []})
