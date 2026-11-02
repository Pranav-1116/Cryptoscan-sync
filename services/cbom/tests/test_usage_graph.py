"""CBOM relationships as graph edges, each carrying its evidence."""

from __future__ import annotations

import pytest

from cbom import usage_graph as ug

PROFILES = [
    {"asset": {"algorithm": "AES-256-GCM", "purpose": "TLS"},
     "observed_classes": ["RUNTIME_OBSERVED", "NETWORK_OBSERVED"],
     "evidence_ids": ["RUNTIME-1", "NET-1"], "confidence": "VERY_HIGH",
     "usage": "OBSERVED"},
    {"asset": {"algorithm": "RSA-2048", "purpose": "SIGNATURE"},
     "observed_classes": [], "classes": {"IMPORTED": {"count": 1}},
     "evidence_ids": ["SBOM-1"], "confidence": "LOW", "usage": "CANDIDATE_ONLY"},
]

PATHS = {"paths": [{
    "endpoint": "payments.bank.example:443", "evidence_id": "NET-1",
    "class": "NETWORK_OBSERVED", "tls_version": "TLS1.3",
    "cipher_suite": "TLS_AES_256_GCM_SHA384", "certificate_ref": "cert-9281",
    "from": "client", "to": "External LB"}]}

RECONCILED = {"conflicts": [{
    "field": "version", "kind": "VERSION_CONFLICT",
    "values": {"container": "3.0.13", "runtime": "3.0.11"},
    "evidence": {"container": "C-1", "runtime": "R-1"},
    "statement": "version has 2 observed values across 2 source(s)"}]}


class _Engine:
    def __init__(self):
        self.nodes: dict[str, dict] = {}
        self.edges: list[dict] = []

    def add_node(self, node_id, *, kind, **props):
        self.nodes[node_id] = {"id": node_id, "kind": kind, **props}

    def add_edge(self, src, dst, relation, **meta):
        self.edges.append({"from": src, "to": dst, "relation": relation, **meta})


# --------------------------------------------------------------------------- #
# usage edges


def test_an_observed_algorithm_is_an_observed_edge():
    body = ug.usage_edges(PROFILES, system="payments-api")
    observed = next(edge for edge in body["edges"] if edge["to"] == "algorithm:AES-256-GCM")
    assert observed["from"] == "system:payments-api"
    assert observed["provenance"] == "OBSERVED"
    assert observed["evidence_ids"] == ["NET-1", "RUNTIME-1"]
    assert observed["confidence"] == "VERY_HIGH"


def test_an_sbom_only_algorithm_is_a_declared_edge():
    body = ug.usage_edges(PROFILES, system="payments-api")
    declared = next(edge for edge in body["edges"] if edge["to"] == "algorithm:RSA-2048")
    assert declared["provenance"] == "DECLARED"
    assert declared["usage"] == "CANDIDATE_ONLY"


def test_an_algorithm_with_no_evidence_gets_no_edge():
    body = ug.usage_edges([{"asset": {"algorithm": "AES-128"}, "evidence_ids": []}],
                          system="payments-api")
    assert body["edges"] == [] and body["undeclared"] == ["AES-128"]
    assert "no evidence" in body["statement"]


def test_a_usage_graph_needs_a_subject():
    with pytest.raises(ValueError):
        ug.usage_edges(PROFILES)


def test_the_subject_can_be_an_application_or_a_component():
    assert ug.usage_edges(PROFILES, application="payments")["edges"][0]["from"] == \
        "application:payments"
    assert ug.usage_edges(PROFILES, component="openssl")["edges"][0]["from"] == \
        "component:openssl"


# --------------------------------------------------------------------------- #
# conflicts


def test_a_conflict_becomes_an_edge_with_both_evidence_ids():
    body = ug.conflict_edges(RECONCILED)
    edge = body["edges"][0]
    assert (edge["from"], edge["kind"], edge["to"]) == \
        ("source:container", "CONFLICTS_WITH", "source:runtime")
    assert edge["evidence_ids"] == ["C-1", "R-1"]
    assert edge["field"] == "version"
    assert edge["left_value"] == "3.0.13" and edge["right_value"] == "3.0.11"


def test_a_conflict_is_never_resolved_into_an_edge():
    body = ug.conflict_edges({**RECONCILED, "resolved": [
        {"field": "version", "value": None, "basis": "RUNTIME_OBSERVED"}]})
    assert all("resolved" not in edge for edge in body["edges"])
    assert "no conflict is resolved" in body["statement"]


def test_agreeing_sources_produce_no_conflict_edges():
    body = ug.conflict_edges({"conflicts": []})
    assert body["edges"] == [] and "the sources agree" in body["statement"]


# --------------------------------------------------------------------------- #
# TLS


def test_a_terminator_owns_its_algorithms_not_the_application():
    body = ug.tls_edges(PATHS)
    negotiates = {edge["to"] for edge in body["edges"] if edge["kind"] == "NEGOTIATES"}
    assert negotiates == {"algorithm:AES-256-GCM", "algorithm:SHA-384"}
    assert all(edge["from"] == "endpoint:payments.bank.example:443" for edge in body["edges"])
    assert "belong to the terminator" in body["statement"]


def test_a_terminator_edges_to_its_certificate():
    body = ug.tls_edges(PATHS)
    edge = next(row for row in body["edges"] if row["kind"] == "TERMINATES")
    assert edge["to"] == "certificate:cert-9281" and edge["evidence_ids"] == ["NET-1"]


def test_a_hop_with_no_endpoint_is_skipped():
    assert ug.tls_edges({"paths": [{"evidence_id": "N-1"}]})["edges"] == []


# --------------------------------------------------------------------------- #
# the whole graph


def test_build_graph_counts_each_family():
    body = ug.build_graph(PROFILES, reconciled=RECONCILED, paths=PATHS,
                          system="payments-api")
    assert body["families"] == {"usage": 2, "conflicts": 1, "tls": 4}
    assert len(body["edges"]) == 7
    assert body["provenance"]["OBSERVED"] == 6 and body["provenance"]["DECLARED"] == 1


def test_edges_are_written_only_with_evidence():
    body = ug.build_graph(PROFILES, reconciled=RECONCILED, paths=PATHS,
                          system="payments-api")
    engine = _Engine()
    applied = ug.apply_graph(engine, body["edges"])
    assert applied["written"] == len(body["edges"]) and applied["refused"] == []
    assert applied["by_provenance"] == {"DECLARED": 1, "OBSERVED": 6}


def test_an_edge_without_evidence_is_refused():
    engine = _Engine()
    applied = ug.apply_graph(engine, [{"from": "system:a", "kind": "USES_CRYPTO",
                                       "to": "algorithm:X", "evidence_ids": []}])
    assert applied["written"] == 0 and applied["refused"]
    assert engine.edges == []


def test_nodes_are_typed_from_their_ids():
    engine = _Engine()
    ug.apply_graph(engine, ug.build_graph(PROFILES, paths=PATHS,
                                          system="payments-api")["edges"])
    kinds = {name: payload["kind"] for name, payload in engine.nodes.items()}
    assert kinds["system:payments-api"] == "SYSTEM"
    assert kinds["algorithm:AES-256-GCM"] == "CRYPTO_ALGORITHM"
    assert kinds["endpoint:payments.bank.example:443"] == "ENDPOINT"
    assert kinds["certificate:cert-9281"] == "CERTIFICATE"


def test_coverage_travels_with_the_graph():
    note = ug.coverage_note({"systems_total": 100, "systems_inspected": 62,
                             "assets_discovered": 12})
    assert note["completeness"] == "PARTIAL" and note["quotable_as_total"] is False
    assert "not the estate" in note["statement"]
