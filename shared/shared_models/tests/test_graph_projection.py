"""Graph-projection contract tests (gap analysis §C: Neo4j is rebuildable)."""

from __future__ import annotations

import pytest

from shared_models.graph_projection import (
    PROJECTION_SCHEMA, PROVEN, UNKNOWN,
    build_projection, same_logical_graph,
)

ASSETS = [
    {"identifier": "asset:rsa-key", "evidence_ids": ["ev-1", "ev-2"],
     "mapping_results": {"policy": "PQC-2030"}},
    {"identifier": "asset:cert", "evidence_ids": ["ev-3"], "mapping_results": {}},
]
RELS = [
    {"subject": "asset:cert", "predicate": "USES", "object": "asset:rsa-key",
     "evidence_ids": ["ev-3"]},
    {"subject": "asset:rsa-key", "predicate": "DEPLOYED_IN", "object": "app:payments",
     "evidence_ids": []},
]


def test_rebuild_from_the_same_rows_is_the_same_logical_graph():
    a = build_projection(assets=ASSETS, relationships=RELS)
    b = build_projection(assets=list(ASSETS), relationships=list(RELS))
    assert a["graph_digest"] == b["graph_digest"]
    assert same_logical_graph(a, b)


def test_row_order_never_changes_the_graph():
    a = build_projection(assets=ASSETS, relationships=RELS)
    b = build_projection(assets=list(reversed(ASSETS)), relationships=list(reversed(RELS)))
    assert same_logical_graph(a, b)


def test_duplicates_collapse_and_evidence_unions():
    doubled = ASSETS + ASSETS + [{"identifier": "asset:rsa-key",
                                  "evidence_ids": ["ev-9"], "mapping_results": {}}]
    proj = build_projection(assets=doubled, relationships=RELS + RELS)
    assert proj["node_count"] == 2
    assert proj["edge_count"] == 2
    assert proj["duplicates_collapsed"] >= 1
    rsa = next(n for n in proj["nodes"] if n["identifier"] == "asset:rsa-key")
    assert rsa["evidence_ids"] == ["ev-1", "ev-2", "ev-9"], "evidence unions on rebuild"
    single = build_projection(assets=ASSETS, relationships=RELS)
    assert not same_logical_graph(proj, single), "added evidence is a different record set"


def test_a_row_without_an_identifier_is_refused():
    with pytest.raises(ValueError):
        build_projection(assets=[{"evidence_ids": ["ev-1"]}], relationships=[])


def test_a_relationship_missing_an_end_is_refused():
    with pytest.raises(ValueError):
        build_projection(assets=[], relationships=[
            {"subject": "a", "predicate": "LINKS", "object": ""}])


def test_an_edge_without_evidence_is_unknown_never_proven():
    proj = build_projection(assets=ASSETS, relationships=RELS)
    by_edge = {(e["subject"], e["predicate"], e["object"]): e for e in proj["edges"]}
    unproven = by_edge[("asset:rsa-key", "DEPLOYED_IN", "app:payments")]
    assert unproven["provenance"] == UNKNOWN
    proven = by_edge[("asset:cert", "USES", "asset:rsa-key")]
    assert proven["provenance"] == PROVEN
    assert proj["unproven_edges"] == 1


def test_mapping_results_travel_with_the_node():
    proj = build_projection(assets=ASSETS, relationships=RELS)
    rsa = next(n for n in proj["nodes"] if n["identifier"] == "asset:rsa-key")
    assert rsa["mapping_results"] == {"policy": "PQC-2030"}


def test_a_different_estate_is_a_different_graph():
    a = build_projection(assets=ASSETS, relationships=RELS)
    b = build_projection(assets=ASSETS[:1], relationships=[])
    assert not same_logical_graph(a, b)


def test_schema_constant_is_stable():
    proj = build_projection(assets=ASSETS, relationships=RELS)
    assert proj["schema"] == PROJECTION_SCHEMA
    assert proj["graph_digest"].startswith("sha256:")
