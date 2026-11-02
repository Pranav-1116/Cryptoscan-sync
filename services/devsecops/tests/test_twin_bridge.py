"""Twin edges carry their evidence, and an unattributable edge is not written.

The graph is where "in the SBOM" and "observed running" must stay different
things: provenance is decided by the evidence kind, never by the edge label.
"""

from __future__ import annotations

from datetime import date


from devsecops import sbom_evidence as evidence


class _Engine:
    """Minimal duck-typed engine: the bridge must not need the real one."""

    def __init__(self):
        self.nodes: dict[str, dict] = {}
        self.edges: list[dict] = []

    def add_node(self, node_id, *, kind, **props):
        self.nodes[node_id] = {"id": node_id, "kind": kind, **props}

    def add_edge(self, src, dst, relation, **meta):
        self.edges.append({"from": src, "to": dst, "relation": relation, **meta})


DIGEST = "sha256:" + "a" * 64


def _edges(*, with_evidence=True):
    base = {"evidence_id": "EV-1" if with_evidence else None, "evidence_type": "SBOM",
            "source": "scan", "observed_at": "2026-11-02", "confidence": "HIGH"}
    return [
        {**base, "from": "sbom:S-1", "kind": "DESCRIBED_BY", "to": "ghcr.io/bank/api"},
        {**base, "from": "ghcr.io/bank/api", "kind": "CONTAINS", "to": "pkg:deb/openssl@3.0.13"},
    ]


def test_an_sbom_edge_is_declared_not_observed():
    engine = _Engine()
    applied = evidence.apply_twin_edges(engine, _edges())
    assert applied["written"] == 2
    assert applied["by_provenance"] == {"DECLARED": 2}
    assert {edge["provenance"] for edge in engine.edges} == {"DECLARED"}


def test_a_deployment_observation_is_observed():
    engine = _Engine()
    edges = [{**_edges()[1], "evidence_type": "DEPLOYMENT", "evidence_id": "K8S-1"}]
    evidence.apply_twin_edges(engine, edges)
    assert engine.edges[0]["provenance"] == "OBSERVED"


def test_a_capability_is_inferred():
    engine = _Engine()
    edges = [{**_edges()[1], "evidence_type": "CAPABILITY"}]
    evidence.apply_twin_edges(engine, edges)
    assert engine.edges[0]["provenance"] == "INFERRED"


def test_an_edge_with_no_evidence_id_is_refused():
    engine = _Engine()
    applied = evidence.apply_twin_edges(engine, _edges(with_evidence=False))
    assert applied["written"] == 0
    assert len(applied["refused"]) == 2
    assert "evidence id" in applied["refused"][0]["reason"]
    assert engine.edges == []


def test_an_edge_with_no_endpoint_is_refused():
    engine = _Engine()
    applied = evidence.apply_twin_edges(engine, [{"evidence_id": "EV", "from": "",
                                                 "kind": "CONTAINS", "to": "x"}])
    assert applied["written"] == 0 and applied["refused"]


def test_nodes_are_typed_by_their_id():
    engine = _Engine()
    evidence.apply_twin_edges(engine, [
        {"evidence_id": "EV", "evidence_type": "SBOM", "from": "sbom:S-1", "kind": "CONTAINS",
         "to": "pkg:deb/openssl@3.0.13"},
        {"evidence_id": "EV", "evidence_type": "REGISTER", "from": "application:payments",
         "kind": "SERVES", "to": "business:cards"},
    ])
    assert engine.nodes["sbom:S-1"]["kind"] == "SBOM"
    assert engine.nodes["pkg:deb/openssl@3.0.13"]["kind"] == "COMPONENT"
    assert engine.nodes["application:payments"]["kind"] == "APPLICATION"
    assert engine.nodes["business:cards"]["kind"] == "BUSINESS_SYSTEM"


def test_the_component_workload_and_artifact_nodes_are_typed():
    engine = _Engine()
    record = evidence.SbomRecord("S-9", evidence.ArtifactIdentity("ghcr.io/bank/api", DIGEST),
                                 ({"name": "openssl", "version": "3.0.13"},))
    observation = evidence.DeploymentObservation(
        deployment="payments/api-1", environment="PRODUCTION", artifact=record.artifact,
        workload="payments/api-1", observed_at=date(2026, 11, 2), evidence_id="K8S-1")
    evidence.apply_twin_edges(
        engine, evidence.twin_edges(record, deployments=[observation],
                                    application="payments")["edges"])
    kinds = {node: payload["kind"] for node, payload in engine.nodes.items()}
    assert kinds["component:openssl"] == "COMPONENT"
    assert kinds["artifact:ghcr.io/bank/api"] == "ARTIFACT"
    assert kinds["workload:payments/api-1"] == "WORKLOAD"
    assert kinds["deployment:payments/api-1"] == "DEPLOYMENT"


def test_unknown_evidence_kinds_are_reported_not_hidden():
    engine = _Engine()
    applied = evidence.apply_twin_edges(engine, [{**_edges()[1], "evidence_type": "RUMOUR"}])
    assert applied["unattributed_kinds"] == 1
    assert engine.edges[0]["provenance"] == "UNATTRIBUTED"
    assert "UNATTRIBUTED" in applied["statement"]


def test_the_evidence_id_and_confidence_travel_onto_the_edge():
    engine = _Engine()
    evidence.apply_twin_edges(engine, _edges())
    edge = engine.edges[0]
    assert edge["evidence_ref"] == "EV-1"
    assert edge["confidence"] == "HIGH"
    assert edge["source"] == "scan"
    assert edge["observed_at"] == "2026-11-02"


def test_real_twin_edges_from_a_record_are_bridgeable():
    engine = _Engine()
    record = evidence.SbomRecord("S-9", evidence.ArtifactIdentity("ghcr.io/bank/api", DIGEST),
                                 ({"name": "openssl", "version": "3.0.13"},),
                                 created_at=date(2026, 11, 2))
    observation = evidence.DeploymentObservation(
        deployment="payments/api-1", environment="PRODUCTION",
        artifact=evidence.ArtifactIdentity("ghcr.io/bank/api", DIGEST),
        workload="pod/payments/api-1", observed_at=date(2026, 11, 2), evidence_id="K8S-1")
    edges = evidence.twin_edges(record, deployments=[observation], application="payments")
    applied = evidence.apply_twin_edges(engine, edges["edges"])
    assert applied["written"] == len(edges["edges"])
    assert "OBSERVED" in applied["by_provenance"]
    assert "DECLARED" in applied["by_provenance"]


def test_a_component_with_no_observation_has_no_observed_edge():
    engine = _Engine()
    record = evidence.SbomRecord("S-9", evidence.ArtifactIdentity("ghcr.io/bank/api", DIGEST),
                                 ({"name": "openssl", "version": "3.0.13"},))
    applied = evidence.apply_twin_edges(engine, evidence.twin_edges(record)["edges"])
    assert applied["by_provenance"].get("OBSERVED", 0) == 0


def test_every_evidence_kind_twin_edges_emits_has_a_provenance_class():
    engine = _Engine()
    record = evidence.SbomRecord("S-9", evidence.ArtifactIdentity("ghcr.io/bank/api", DIGEST),
                                 ({"name": "openssl", "version": "3.0.13",
                                   "crypto_relevant": True},))
    observation = evidence.DeploymentObservation(
        deployment="payments/api-1", environment="PRODUCTION", artifact=record.artifact,
        workload="payments/api-1", observed_at=date(2026, 11, 2), evidence_id="K8S-1")
    edges = evidence.twin_edges(record, deployments=[observation], application="payments",
                                business_system="cards",
                                algorithms={"openssl": ["AES-256-GCM"]})["edges"]
    kinds = {str(edge["evidence_type"]).upper() for edge in edges}
    assert kinds - set(evidence.PROVENANCE_FOR_EVIDENCE) == set()
    applied = evidence.apply_twin_edges(engine, edges)
    assert applied["unattributed_kinds"] == 0
    assert applied["by_provenance"]["INFERRED"] >= 1
