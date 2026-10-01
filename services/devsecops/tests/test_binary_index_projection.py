"""The binary history projection stays bounded and evidence-only."""
from __future__ import annotations

from devsecops.artifact_store import _bounded_index_json, _indexed_observation


def test_projection_redacts_material_and_bounds_nested_parser_data():
    projected = _indexed_observation({
        "path": "/tmp/app", "format": "zip", "parsed": True,
        "crypto": {"algorithms": ["AES"], "private_key": "do-not-store"},
        "android": {"apk_signing_block": {"present": True, "pair_ids": list(range(500))}},
        "parse_note": "x" * 10000,
    }, artifact_id="a", scan_record_id="s", tenant_id="tenant-a")
    assert projected["crypto"] == {"algorithms": ["AES"]}
    assert "private_key" not in str(projected)
    assert len(projected["parser_metadata"]["android"]["apk_signing_block"]["pair_ids"]) == 120
    assert len(projected["parser_metadata"]["parse_note"]) == 2000


def test_projection_distinguishes_unsupported_from_partial_parse():
    unsupported = _indexed_observation({"path": "x", "parsed": False,
                                        "parse_note": "unrecognised container format"},
                                       artifact_id="a", scan_record_id="s", tenant_id=None)
    partial = _indexed_observation({"path": "y", "parsed": False,
                                    "parse_error": "truncated header"},
                                   artifact_id="a", scan_record_id="s", tenant_id=None)
    assert unsupported["evidence_state"] == "unsupported"
    assert partial["evidence_state"] == "partial"


def test_projection_handles_unknown_values_without_serialization_blowup():
    value = _bounded_index_json({"nested": {"value": object()}})
    assert isinstance(value["nested"]["value"], str)
