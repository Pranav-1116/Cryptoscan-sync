"""PQC handoff: a CBOM inventories, the PQC engine decides, and neither lies.

The review's items 14 and 15: ``quantumVulnerable: true|false|null`` cannot say
"Grover weakens this but it is still acceptable", cannot say "hybrid", and puts
the verdict in a document that only ever observed an algorithm. These tests pin
the replacement vocabulary and, more importantly, the things it refuses to claim.
"""

from __future__ import annotations

import pytest

from cbom import pqc_handoff as pq


def _row(*assets, **kwargs):
    return pq.handoff(list(assets), **kwargs)


def _one(algorithm, **asset):
    return _row({"algorithm": algorithm, **asset})["rows"][0]


# --------------------------------------------------------------------------- #
# status vocabulary


def test_a_shor_vulnerable_key_is_quantum_sensitive():
    row = _one("RSA-2048", key_size=2048, purpose="TLS")
    assert row["quantum_status"] == "QUANTUM_SENSITIVE"
    assert row["status_basis"] == "REGISTRY_SHOR"
    assert row["algorithm_class"] == "PUBLIC_KEY"


def test_a_pqc_algorithm_is_resistant_and_needs_no_migration():
    row = _one("ML-KEM-768", purpose="KEY_EXCHANGE")
    assert row["quantum_status"] == "QUANTUM_RESISTANT"
    assert row["migration_priority"] == "NONE"
    assert row["recommended_replacement"] is None


def test_a_hybrid_is_hybrid_not_resistant():
    row = _one("X25519MLKEM768", purpose="KEY_EXCHANGE")
    assert row["quantum_status"] == "HYBRID"
    assert row["quantum_risk"] == "NONE"
    assert row["migration_priority"] == "NONE"


def test_grover_impact_depends_on_size_not_on_a_boolean():
    """AES-128 and AES-256 are both "not Shor-broken" and are not the same answer."""
    weak = _one("AES-128-GCM", key_size=128, purpose="DATA_AT_REST")
    strong = _one("AES-256-GCM", key_size=256, purpose="DATA_AT_REST")
    assert weak["quantum_status"] == "TRANSITIONAL"
    assert weak["recommended_replacement"] == "AES-256"
    assert strong["quantum_status"] == "CLASSICAL_ONLY"
    assert strong["migration_priority"] == "NONE"


def test_an_unregistered_algorithm_is_unknown_and_flagged_for_review():
    row = _one("ACME-CIPHER-9")
    assert row["quantum_status"] == "UNKNOWN"
    assert row["quantum_risk"] == "UNKNOWN"
    assert row["requires_review"] is True
    assert row["migration_priority"] == "UNKNOWN"


def test_an_asset_with_no_algorithm_is_not_assessed():
    assert pq.quantum_status(None)["status"] == "NOT_ASSESSED"
    assert pq.quantum_status("  ")["basis"] == "NO_ALGORITHM"


def test_a_classically_broken_algorithm_is_named_as_such():
    row = _one("3DES", purpose="ENCRYPTION")
    assert row["classically_broken"] is True
    assert row["quantum_risk"] == "CRITICAL"
    assert "classically broken" in row["statement"]
    assert row["recommended_replacement"]


def test_a_hash_is_never_replaced_by_a_cipher():
    assert _one("SHA-1")["recommended_replacement"] == "SHA-256"
    assert _one("MD5")["recommended_replacement"] == "SHA-256"


@pytest.mark.parametrize("algorithm,expected", [
    ("RSA-2048", "PUBLIC_KEY"), ("ML-KEM-768", "KEM"), ("ML-DSA-65", "SIGNATURE"),
    ("AES-256-GCM", "SYMMETRIC"), ("SHA-256", "HASH"), ("TLS1.3", "PROTOCOL"),
    ("WHO-KNOWS", "UNKNOWN"),
])
def test_algorithm_class_comes_from_the_registry(algorithm, expected):
    assert pq.algorithm_class(algorithm) == expected


# --------------------------------------------------------------------------- #
# priority: risk, then evidence, and never downwards


def test_a_capability_and_a_runtime_observation_rank_differently():
    capability = _one("AES-128-GCM", key_size=128, usage="CAPABILITY")
    observed = _one("AES-128-GCM", key_size=128, usage="RUNTIME")
    assert capability["migration_priority"] == "MEDIUM"
    assert observed["migration_priority"] == "HIGH"
    assert observed["priority_escalated_by"] == ["OBSERVED_USAGE:RUNTIME"]


def test_confidentiality_use_of_a_shor_vulnerable_key_is_immediate():
    row = _one("ECDH-P256", purpose="KEY_EXCHANGE")
    assert row["migration_priority"] == "IMMEDIATE"
    assert "HNDL_CONFIDENTIALITY_PURPOSE" in row["priority_escalated_by"]


def test_signature_use_is_not_an_hndl_escalation():
    row = _one("ECDSA-P256", purpose="SIGNATURE")
    assert row["migration_priority"] == "HIGH"
    assert "HNDL_CONFIDENTIALITY_PURPOSE" not in row["priority_escalated_by"]


def test_evidence_never_lowers_a_priority():
    """A capability is lower priority only because it was never escalated."""
    rows = _row({"algorithm": "RSA-2048", "purpose": "TLS", "usage": "CAPABILITY"},
                {"algorithm": "RSA-2048", "purpose": "TLS", "usage": "VERIFIED"})["rows"]
    assert [row["migration_priority"] for row in rows] == ["IMMEDIATE", "IMMEDIATE"]


# --------------------------------------------------------------------------- #
# the handoff itself


def test_rows_are_ordered_most_urgent_first():
    body = _row({"algorithm": "AES-256-GCM", "key_size": 256},
                {"algorithm": "RSA-2048", "purpose": "TLS"},
                {"algorithm": "ACME-CIPHER-9"})
    assert [row["algorithm"] for row in body["rows"]] == [
        "RSA-2048", "AES-256-GCM", "ACME-CIPHER-9"]


def test_an_asset_without_an_algorithm_is_refused_not_guessed():
    body = _row({"purpose": "TLS"})
    assert body["rows"] == [] and body["refused"]
    assert "names no algorithm" in body["refused"][0]["reason"]


def test_summary_counts_only_what_needs_migration():
    body = _row({"algorithm": "RSA-2048", "purpose": "TLS"},
                {"algorithm": "ML-KEM-768"},
                {"algorithm": "AES-256-GCM", "key_size": 256},
                {"algorithm": "ACME-CIPHER-9"})
    summary = body["summary"]
    assert summary["assets"] == 4
    assert summary["requiring_migration"] == 1
    assert summary["requires_review"] == 1
    assert summary["by_priority"]["IMMEDIATE"] == 1


def test_migration_status_defaults_to_not_started_and_is_carried_through():
    assert _one("RSA-2048")["migration_status"] == "NOT_STARTED"
    assert _one("RSA-2048", migration_status="in_progress")["migration_status"] == "IN_PROGRESS"


def test_every_row_carries_the_evidence_it_was_built_from():
    row = _one("RSA-2048", purpose="TLS", evidence_ids=["NET-9", "RUNTIME-2", "NET-9"])
    assert row["evidence_ids"] == ["NET-9", "RUNTIME-2"], "deduplicated and sorted"


# --------------------------------------------------------------------------- #
# the document side: a status may travel, a decision may not


def test_the_status_travels_as_a_namespaced_property_not_a_boolean():
    props = {row["name"]: row["value"] for row in pq.component_properties("RSA-2048", 2048)}
    assert props["cryptoscan:quantum_status"] == "QUANTUM_SENSITIVE"
    assert props["cryptoscan:algorithm_class"] == "PUBLIC_KEY"
    assert props["cryptoscan:quantum_status_basis"] == "REGISTRY_SHOR"
    assert "quantumVulnerable" not in props


def test_an_unknown_algorithm_marks_the_component_for_review():
    props = {row["name"]: row["value"] for row in pq.component_properties("ACME-9")}
    assert props["cryptoscan:requires_review"] == "true"


def test_reading_a_status_back_tolerates_old_documents():
    modern = {"properties": [{"name": "cryptoscan:quantum_status", "value": "HYBRID"}]}
    assert pq.status_from_component(modern) == "HYBRID"
    assert pq.status_from_component(
        {"cryptoProperties": {"quantumVulnerable": True}}) == "QUANTUM_SENSITIVE"
    assert pq.status_from_component(
        {"cryptoProperties": {"quantumVulnerable": False}}) == "CLASSICAL_ONLY"
    assert pq.status_from_component({}) is None


def test_a_boolean_is_only_derived_where_it_is_defensible():
    assert pq.vulnerable_from_status("QUANTUM_SENSITIVE") is True
    assert pq.vulnerable_from_status("CLASSICAL_ONLY") is False
    assert pq.vulnerable_from_status("TRANSITIONAL") is None
    assert pq.vulnerable_from_status("UNKNOWN") is None
    assert pq.vulnerable_from_status(None) is None


def test_handing_off_a_document_reads_platform_usage_and_defaults_to_unobserved():
    document = {"components": [
        {"bom-ref": "crypto/RSA-2048", "name": "RSA-2048",
         "cryptoProperties": {"algorithmProperties": {"algorithm": "RSA-2048",
                                                     "parameterSetIdentifier": "2048"}},
         "properties": [{"name": "cryptoscan:usage", "value": "RUNTIME"},
                        {"name": "cryptoscan:evidence_id", "value": "RUNTIME-4"}]},
        {"bom-ref": "crypto/AES-256-GCM", "name": "AES-256-GCM",
         "cryptoProperties": {"algorithmProperties": {"algorithm": "AES-256-GCM",
                                                     "parameterSetIdentifier": "256"}}},
    ]}
    body = pq.handoff_from_cbom(document)
    rows = {row["algorithm"]: row for row in body["rows"]}
    assert rows["RSA-2048"]["migration_priority"] == "IMMEDIATE"
    assert rows["RSA-2048"]["evidence_ids"] == ["RUNTIME-4"]
    assert rows["AES-256-GCM"]["usage"] is None
    assert rows["AES-256-GCM"]["migration_priority"] == "NONE"
    assert body["source"]["components"] == 2
