from copy import deepcopy
from datetime import datetime, timezone
import math
import pytest
from shared_models.operational_dependencies import (
    MODES,
    condition,
    validate_assertion,
    project_operational_dependencies,
    compare_operational_impacts,
)
from shared_models.process_impact import classify_systems
from shared_models.traversal_evidence import metadata, native_properties, path_evidence

NOW = datetime(2026, 10, 18, tzinfo=timezone.utc)


@pytest.mark.parametrize("mode", MODES)
def test_modes_never_claim_failure_probability_or_guaranteed_safe_delay(mode):
    raw = {"mode": mode, "evidence_ref": "test/1", "assumptions": ["Provider unavailable to this function"]}
    before = deepcopy(raw)
    answer = condition(raw, known_systems={"pay"})
    assert answer["mode"] == mode and answer["verified"] is False
    assert answer["failure_probability"] is None and answer["safe_delay_seconds"] is None
    assert answer["conditional_outcome"] and answer["assertion_status"] == "DECLARED"
    assert raw == before


@pytest.mark.parametrize(
    "raw",
    [
        False,
        [],
        "HARD",
        {"mode": "soft"},
        {"mode": "OPTIONAL", "failover_system_ids": ["alt"]},
        {"mode": "HARD", "buffer_capacity_messages": 1},
        {"mode": "ASYNC_BUFFERED", "buffer_capacity_messages": -1},
        {"mode": "ASYNC_BUFFERED", "buffer_capacity_messages": True},
        {"mode": "ASYNC_BUFFERED", "buffer_capacity_messages": 1.5},
        {"mode": "ASYNC_BUFFERED", "buffer_retention_seconds": math.inf},
        {"mode": "ASYNC_BUFFERED", "buffer_retention_seconds": 0},
        {"mode": "HARD", "failure_probability": 0.9},
        {"mode": "FAILOVER", "failover_system_ids": ["alt", "alt"]},
        {"mode": "FAILOVER", "failover_system_ids": ["system:alt"]},
        {"mode": "HARD", "assumptions": [" "]},
        {"mode": "HARD", "assumptions": ["x"] * 21},
    ],
)
def test_invalid_metadata_is_rejected_on_write_and_unknown_on_read(raw):
    with pytest.raises(ValueError):
        validate_assertion(raw)
    result = condition(raw)
    assert result["mode"] == "UNKNOWN" and result["assertion_status"] == "INVALID"


def test_legacy_mode_is_unknown_not_inferred_from_role_or_relation():
    c = condition(None)
    assert c["mode"] == "UNKNOWN" and c["assertion_status"] == "UNSPECIFIED"
    edge = {
        "from": "a",
        "to": "b",
        "label": "CALLS",
        "role": "PRIMARY",
        "source": "observed",
        "evidence_ref": "scanner/1",
    }
    assert path_evidence(["a", "b"], [edge], now=NOW)["edges"][0]["operational_condition"]["mode"] == "UNKNOWN"


def test_failover_references_are_identity_context_only_and_not_assumed_independent():
    c = condition(
        {"mode": "FAILOVER", "failover_system_ids": ["unknown", "alt"]},
        known_systems={"alt", "provider"},
        consumer="pay",
        provider="provider",
    )
    assert c["failover_references"]["loaded_system_ids"] == ["alt"]
    assert c["failover_references"]["not_in_loaded_registry"] == ["unknown"]
    assert any("independence" in gap for gap in c["gaps"])
    assert c["verified"] is False
    invalid = condition(
        {"mode": "FAILOVER", "failover_system_ids": ["pay"]}, known_systems={"pay"}, consumer="pay", provider="provider"
    )
    assert invalid["failover_references"]["invalid_self_or_provider_ids"] == ["pay"]


def test_declared_queue_size_zero_and_retention_do_not_produce_a_buffering_horizon():
    result = condition({"mode": "ASYNC_BUFFERED", "buffer_capacity_messages": 0, "buffer_retention_seconds": 60})
    assert result["assertion"]["buffer_capacity_messages"] == 0
    assert result["safe_delay_seconds"] is None
    assert any("headroom" in gap for gap in result["gaps"])


def test_native_codec_and_explicit_clear_survive_without_nested_neo4j_properties():
    raw = {"operational_dependency": {"mode": "OPTIONAL"}}
    props = native_properties(raw)
    assert "operational_dependency" not in props
    assert metadata(props)["operational_dependency"] == raw["operational_dependency"]
    assert native_properties({"operational_dependency": None})["operational_dependency_json"] is None
    assert metadata({"operational_dependency": None})["operational_dependency"] is None
    corrupt = metadata({"operational_dependency_json": "{broken"})
    assert condition(corrupt["operational_dependency"])["mode"] == "UNKNOWN"


def projection(edges):
    return project_operational_dependencies(
        edges, classify_systems(["b"], ["a"], ["c"]), known_systems={"a", "b", "c", "alt"}, now=NOW
    )


def test_review_scope_not_sampled_witness_controls_modes_and_excludes_noncurrent_context_labels():
    edges = [
        {"from": "a", "to": "b", "label": "CALLS", "operational_dependency": {"mode": "OPTIONAL"}},
        {"from": "b", "to": "c", "label": "CALLS", "operational_dependency": {"mode": "HARD"}},
        {"from": "a", "to": "c", "label": "CALLS", "operational_dependency": {"mode": "ASYNC_BUFFERED"}},
        {"from": "a", "to": "b", "label": "CONTAINS", "operational_dependency": {"mode": "HARD"}},
        {
            "from": "a",
            "to": "b",
            "label": "DEPENDS_ON",
            "lifecycle_state": "STALE",
            "operational_dependency": {"mode": "HARD"},
        },
        {"from": "b", "to": "alt", "label": "CALLS", "operational_dependency": {"mode": "HARD"}},
    ]
    first = projection(edges)
    assert first["edge_count"] == 3 and first["non_current_edge_count"] == 1
    assert first["mode_counts"] == {"UNKNOWN": 0, "HARD": 1, "OPTIONAL": 1, "FAILOVER": 0, "ASYNC_BUFFERED": 1}
    assert first == projection(list(reversed(edges)))
    assert next(e for e in first["edges"] if e["from"] == "b")["provider_scope"] == "supporting_context"


def test_explanation_cap_does_not_change_counts_or_permit_incomplete_history_diff(monkeypatch):
    import shared_models.operational_dependencies as reducer

    monkeypatch.setattr(reducer, "EDGE_LIMIT", 1)
    result = projection([{"from": "a", "to": "b", "id": str(i)} for i in range(3)])
    assert len(result["edges"]) == 1 and result["edge_count"] == result["mode_counts"]["UNKNOWN"] == 3
    assert (
        compare_operational_impacts({"operational_impact": result}, {"operational_impact": result})["comparable"]
        is False
    )


def test_mode_only_change_diff_ignores_clock_and_never_reconstructs_old_schema():
    old = projection([{"from": "a", "to": "b", "operational_dependency": {"mode": "HARD"}}])
    new = projection([{"from": "a", "to": "b", "operational_dependency": {"mode": "OPTIONAL"}}])
    diff = compare_operational_impacts({"operational_impact": old}, {"impact": {"operational_impact": new}})
    assert diff["comparable"] and len(diff["changed_edges"]) == 1
    assert diff["added_edges"] == diff["removed_edges"] == []
    assert not compare_operational_impacts({}, {"operational_impact": new})["comparable"]
