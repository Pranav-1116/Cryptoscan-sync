from copy import deepcopy
from datetime import datetime, timezone

from cbom.unified_cascade import unified_cascade
from shared_models.coverage import SOURCE_SCHEMA, collection_read

NOW = datetime(2026, 10, 18, tzinfo=timezone.utc)


def test_horizon_does_not_expand_classification_and_unresolved_links_use_original_input():
    snapshot = {
        "systems": [{"id": s, "name": s} for s in "abcd"],
        "dependencies": [
            {"source": "a", "target": "b", "type": "CALLS"},
            {"source": "b", "target": "c", "type": "CALLS"},
            {"source": "b", "target": "ghost", "type": "CALLS"},
            {"source": "b", "target": "asset:x", "type": "IMPORTS_CRYPTO"},
            {"source": "b", "target": "d", "type": "CALLS", "lifecycle_state": "STALE"},
        ],
        "source_coverage": {"schema": SOURCE_SCHEMA, "collections": {"systems": collection_read(4, 20)}},
    }
    original = deepcopy(snapshot)
    result = unified_cascade(snapshot, target="a", kind="system", max_depth=1, now=NOW)
    assert result["impact"]["system_classification"]["review_systems"] == ["a", "b"]
    report = result["coverage"]
    assert report["known_horizon_omission"]
    active = next(w for w in report["traversals"] if w["scope"] == "current" and w["direction"] == "downstream")
    assert active["unvisited_neighbour_count"] == 1
    gap = next(g for g in report["missing_links"] if g["name"] == "dependency_endpoint_references")
    assert gap["count"] == 1
    assert gap["denominator"] == 4
    assert snapshot == original


def test_seed_context_and_reference_caps_are_reported_without_changing_exposure():
    snapshot = {
        "systems": [{"id": "a", "name": "a"}, {"id": "b", "name": "b"}],
        "dependencies": [{"source": "b", "target": "a", "type": "CALLS", "evidence_refs": list(range(70))}],
    }
    result = unified_cascade(snapshot, target="a", kind="system", now=NOW)
    assert result["impact"]["system_classification"]["exposure_system_count"] == 2
    assert result["coverage"]["explanation_truncation"]
    listing = next(row for row in result["coverage"]["explanations"] if row["name"] == "witness_evidence_references")
    assert listing["limit"] == 50 and listing["truncated"]
