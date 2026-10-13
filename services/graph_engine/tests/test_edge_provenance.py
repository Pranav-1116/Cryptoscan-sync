"""§4.5 (round 43): every edge carries a provenance class.

An edge added without saying where it came from is UNATTRIBUTED — visibly —
never a silent "known dependency". Builders stamp honest classes: system
dependency rows and declared topology are DECLARED (operator statements),
evidence-derived inventory links are SCANNER_DERIVED. Traversal results
(blast radius, dependents) account for which classes of edges produced the
impact.
"""

from __future__ import annotations

from graph_engine.builders import cypher_writes, payload
from graph_engine.core.edge_provenance import (
    PROVENANCE_DECLARED,
    PROVENANCE_OBSERVED,
    PROVENANCE_SCANNER_DERIVED,
    PROVENANCE_UNATTRIBUTED,
    normalize_provenance,
    provenance_counts,
)
from graph_engine.core.engine import GraphEngine


def test_unstated_provenance_is_visibly_unattributed():
    engine = GraphEngine()
    engine.add_node("system:a", kind="System")
    engine.add_node("system:b", kind="System")
    engine.add_edge("system:a", "system:b", "CALLS")
    edges = engine.to_vis()["edges"]
    assert edges == [{
        "from": "system:a", "to": "system:b", "label": "CALLS",
        "provenance": PROVENANCE_UNATTRIBUTED,
    }]
    assert engine.edge_provenance("system:a", "system:b", "CALLS") == PROVENANCE_UNATTRIBUTED


def test_explicit_provenance_and_extras_survive_vis_round_trip():
    engine = GraphEngine()
    engine.add_node("system:a", kind="System")
    engine.add_node("system:b", kind="System")
    engine.add_edge("system:a", "system:b", "CALLS",
                    provenance=PROVENANCE_OBSERVED, source="runtime traffic probe",
                    observed_at="2026-10-13T00:00:00Z", confidence=0.9,
                    evidence_ref="ev-1")
    vis = engine.to_vis()
    edge = vis["edges"][0]
    assert edge["provenance"] == PROVENANCE_OBSERVED
    assert edge["source"] == "runtime traffic probe"
    assert edge["observed_at"] == "2026-10-13T00:00:00Z"
    assert edge["confidence"] == 0.9
    assert edge["evidence_ref"] == "ev-1"

    restored = GraphEngine.from_vis(vis)
    assert restored.edge_provenance("system:a", "system:b", "CALLS") == PROVENANCE_OBSERVED
    assert restored.to_vis()["edges"][0]["source"] == "runtime traffic probe"


def test_unknown_provenance_values_collapse_to_unattributed_not_guessed():
    assert normalize_provenance("declared") == PROVENANCE_DECLARED
    assert normalize_provenance("scanner-derived") == PROVENANCE_SCANNER_DERIVED
    assert normalize_provenance("observed") == PROVENANCE_OBSERVED
    assert normalize_provenance("definitely-verified-trust-me") == PROVENANCE_UNATTRIBUTED
    assert normalize_provenance(None) == PROVENANCE_UNATTRIBUTED


def test_build_stamps_honest_classes_per_edge_kind():
    engine = GraphEngine().build(
        systems=[{"id": "sys-1", "name": "core", "compliance_scopes": ["PCI"]},
                 {"id": "sys-2", "name": "edge"}],
        assets=[{"id": "ca-1", "algorithm": "RSA-2048", "system_id": "sys-1"}],
        edges=[{"parent_id": "sys-1", "child_id": "sys-2", "relation": "CALLS"}],
        processes=[{"id": "bp-1", "name": "payments", "system_ids": ["sys-1"]}],
        owners=[{"id": "own-1", "name": "alice", "system_ids": ["sys-1"]}],
        certificates=[{"id": "cert-1", "subject": "acme", "system_ids": ["sys-1"]}],
        network_resources=[{"id": "n-1", "endpoint": "api.acme.io", "system_ids": ["sys-1"]}],
        container_images=[{"id": "img-1", "target": "app:latest", "system_ids": ["sys-1"]}],
    )
    # system→system dependency: operator declaration
    assert engine.edge_provenance("system:sys-1", "system:sys-2", "CALLS") == PROVENANCE_DECLARED
    # asset link: scanner-derived from the evidence-chained inventory
    assert engine.edge_provenance("system:sys-1", "asset:ca-1", "USES") == PROVENANCE_SCANNER_DERIVED
    # declared mappings
    assert engine.edge_provenance("system:sys-1", "scope:PCI", "MUST_COMPLY_WITH") == PROVENANCE_DECLARED
    assert engine.edge_provenance("system:sys-1", "process:bp-1", "SUPPORTS") == PROVENANCE_DECLARED
    assert engine.edge_provenance("system:sys-1", "owner:own-1", "OWNED_BY") == PROVENANCE_DECLARED
    # scanner-derived inventories
    assert engine.edge_provenance("system:sys-1", "cert:cert-1", "SECURED_BY") == PROVENANCE_SCANNER_DERIVED
    assert engine.edge_provenance("system:sys-1", "network:n-1", "CONNECTS_TO") == PROVENANCE_SCANNER_DERIVED
    assert engine.edge_provenance("system:sys-1", "container:img-1", "RUNS") == PROVENANCE_SCANNER_DERIVED


def test_declared_topology_edges_are_declared_never_observations():
    engine = GraphEngine().build(
        systems=[{"id": "sys-1", "name": "core"}],
        topology={
            "nodes": [
                {"name": "cdn-edge", "kind": "CDN", "system_ids": ["sys-1"]},
                {"name": "lb-1", "kind": "LB"},
            ],
            "edges": [{"from": "cdn-edge", "to": "lb-1", "relation": "ROUTES_TO"}],
        },
    )
    assert engine.edge_provenance("edge:cdn-edge", "edge:lb-1", "ROUTES_TO") == PROVENANCE_DECLARED
    assert engine.edge_provenance("edge:cdn-edge", "system:sys-1", "TERMINATES_AT") == PROVENANCE_DECLARED


def test_explicit_edge_provenance_in_payload_wins_over_default():
    engine = GraphEngine().build(
        systems=[{"id": "a"}, {"id": "b"}],
        edges=[{"parent_id": "a", "child_id": "b", "relation": "CALLS",
                "provenance": "OBSERVED", "source": "runtime traffic"}],
    )
    assert engine.edge_provenance("system:a", "system:b", "CALLS") == PROVENANCE_OBSERVED
    meta = engine.edge_meta[("system:a", "system:b", "CALLS")]
    assert meta["source"] == "runtime traffic"


def test_blast_radius_accounts_for_edge_provenance_it_followed():
    engine = GraphEngine().build(
        systems=[{"id": "core", "name": "core"}, {"id": "mid", "name": "mid"},
                 {"id": "leaf", "name": "leaf"}, {"id": "orphan", "name": "orphan"}],
        edges=[
            {"parent_id": "core", "child_id": "mid"},   # DECLARED
            {"parent_id": "mid", "child_id": "leaf", "provenance": "OBSERVED"},
            {"parent_id": "orphan", "child_id": "core"},  # not on the path
        ],
    )
    result = engine.blast_radius("core", hops=3)
    assert result["provenance_counts"] == {
        "OBSERVED": 1, "DECLARED": 1, "SCANNER_DERIVED": 0, "INFERRED": 0, "UNATTRIBUTED": 0,
    }
    # dependents: the reverse walk from leaf follows mid->leaf (observed),
    # core->mid (declared) and orphan->core (declared — orphan also depends
    # on the chain, so it honestly counts as a dependent)
    deps = engine.dependents("leaf", hops=3)
    assert deps["provenance_counts"]["OBSERVED"] == 1
    assert deps["provenance_counts"]["DECLARED"] == 2


def test_provenance_counts_lists_every_class_with_honest_zeros():
    counts = provenance_counts([{"provenance": "DECLARED"}, {"provenance": "DECLARED"}, {}])
    assert counts == {
        "OBSERVED": 0, "DECLARED": 2, "SCANNER_DERIVED": 0, "INFERRED": 0, "UNATTRIBUTED": 1,
    }


def test_neo4j_merge_statements_persist_provenance():
    # the store must write what the engine stamps, or the neo4j vis export
    # would collapse provenance back to a bare relation label
    assert "rel.provenance = row.provenance" in cypher_writes.MERGE_CALLS
    assert "r.provenance = row.provenance" in cypher_writes.MERGE_USES
    for stmt in (cypher_writes.MERGE_SUPPORTS, cypher_writes.MERGE_OWNED_BY,
                 cypher_writes.MERGE_COMPLY, cypher_writes.MERGE_DEPLOYED_ON):
        assert "r.provenance = 'DECLARED'" in stmt, stmt.splitlines()[1]
    for stmt in (cypher_writes.MERGE_SECURED_BY, cypher_writes.MERGE_CONNECTS_TO,
                 cypher_writes.MERGE_RUNS):
        assert "r.provenance = 'SCANNER_DERIVED'" in stmt, stmt.splitlines()[1]


def test_neo4j_payload_rows_carry_provenance():
    calls = payload.call_rows([{"parent_id": "a", "child_id": "b"}])
    assert calls[0]["provenance"] == "DECLARED"
    assert calls[0]["source"] == "system_dependencies (operator-declared)"
    observed = payload.call_rows([{"parent_id": "a", "child_id": "b", "provenance": "OBSERVED"}])
    assert observed[0]["provenance"] == "OBSERVED"

    uses = payload.uses_rows([{"id": "ca-1", "system_id": "s-1"}], [])
    assert uses[0]["provenance"] == "SCANNER_DERIVED"
    assert "evidence-chained" in uses[0]["source"]
