"""Review item 12: every relationship carries its own evidence, or it is not drawn."""

from __future__ import annotations

import pytest

from cbom import topology as tp

BASE = {"evidence_id": "NET-1", "observed_at": "2026-11-01T00:00:00Z",
        "source": "network-probe", "evidence_class": "NETWORK_OBSERVED"}
HOPS = [
    {"from": "Internet", "to": "External LB", "role": "LOAD_BALANCER",
     "cipher_suite": "TLS_AES_256_GCM_SHA384", "tls_version": "1.3",
     "evidence_id": "NET-1", "observed_at": "2026-11-01T00:00:00Z"},
    {"from": "External LB", "to": "Internal LB", "role": "LOAD_BALANCER",
     "cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384", "tls_version": "1.2",
     "evidence_id": "NET-2", "observed_at": "2026-11-01T00:00:00Z"},
]


def test_the_reviews_nine_kinds_are_the_whole_vocabulary():
    assert tp.KINDS == ("CONNECTS_TO", "ROUTES_TO", "TERMINATES_TLS", "RE_ENCRYPTS",
                        "PASSTHROUGH", "PROTECTED_BY", "USES_CERTIFICATE", "USES_HSM",
                        "USES_KMS")
    body = tp.build([{**BASE, "kind": "MAGIC", "from": "a", "to": "b"}])
    assert body["edges"] == []
    assert "not one of the nine relationship kinds" in body["refused"][0]["reason"]


def test_an_edge_without_provenance_is_not_written():
    body = tp.build([{"kind": "CONNECTS_TO", "from": "a", "to": "b"}])
    assert body["edges"] == []
    assert body["refused"][0]["reason"] == (
        "a relationship without evidence_id, observed_at, source is fiction and is "
        "not written")
    partial = tp.build([{"kind": "CONNECTS_TO", "from": "a", "to": "b",
                         "evidence_id": "E-1"}])
    assert "observed_at" in partial["refused"][0]["reason"]
    assert "source" in partial["refused"][0]["reason"]


def test_confidence_is_derived_from_the_evidence_never_supplied():
    observed = tp.build([{**BASE, "kind": "CONNECTS_TO", "from": "a", "to": "b"}])
    assert observed["edges"][0]["confidence"] == "OBSERVED"
    declared = tp.build([{"kind": "PROTECTED_BY", "from": "waf", "to": "app",
                          "evidence_id": "CMDB-1",
                          "observed_at": "2026-11-01T00:00:00Z", "source": "cmdb",
                          "evidence_class": "DECLARED"}])
    assert declared["edges"][0]["confidence"] == "DECLARED"


def test_a_claim_that_calls_itself_observed_without_evidence_is_flagged():
    body = tp.build([{**BASE, "kind": "CONNECTS_TO", "from": "a", "to": "b",
                      "confidence": "OBSERVED",
                      "evidence_class": "DECLARED"}])
    assert body["edges"][0]["confidence"] == "DECLARED"
    assert body["overclaimed"][0]["claim_confidence"] == "OBSERVED"
    assert "called themselves observed" in body["statement"]


def test_re_encryption_needs_two_handshakes_in_one_path():
    refused = tp.build([{**BASE, "kind": "RE_ENCRYPTS", "from": "lb", "to": "app"}])
    assert refused["edges"] == []
    assert "two handshakes in one path" in refused["refused"][0]["reason"]
    accepted = tp.build([{**BASE, "kind": "RE_ENCRYPTS", "from": "lb", "to": "app",
                          "handshakes": [{"evidence_id": "NET-1"},
                                         {"evidence_id": "NET-2"}]}])
    assert accepted["edges"][0]["kind"] == "RE_ENCRYPTS"


def test_passthrough_needs_the_session_identifier():
    refused = tp.build([{**BASE, "kind": "PASSTHROUGH", "from": "lb", "to": "app"}])
    assert refused["edges"] == []
    assert "session identifier" in refused["refused"][0]["reason"]
    accepted = tp.build([{**BASE, "kind": "PASSTHROUGH", "from": "lb", "to": "app",
                          "session_id": "TLS-SESS-9"}])
    assert accepted["edges"][0]["kind"] == "PASSTHROUGH"


def test_hops_become_connections_and_terminations_with_evidence():
    claims = tp.from_hops(HOPS)
    body = tp.build(claims["claims"])
    kinds = [edge["kind"] for edge in body["edges"]]
    assert kinds.count("CONNECTS_TO") == 2 and kinds.count("TERMINATES_TLS") == 2
    assert body["confidence"] == {"OBSERVED": 4, "ASSEMBLED": 0, "DECLARED": 0}
    assert all(edge["evidence_id"] for edge in body["edges"])
    assert body["edges"][0]["source"] == "network-probe"


def test_a_hop_that_observed_nothing_derives_no_claim():
    claims = tp.from_hops([{"from": "a", "to": "b", "cipher_suite": "AES128-SHA"}])
    assert claims["claims"] == []


def test_a_certificate_presentation_becomes_a_use_edge():
    body = tp.build(tp.from_hops([], [{"endpoint": "External LB",
                                       "certificate_ref": "CERT-9281",
                                       "evidence_id": "CERT-E1",
                                       "observed_at": "2026-11-01T00:00:00Z"}])["claims"])
    assert body["edges"][0]["kind"] == "USES_CERTIFICATE"
    assert body["edges"][0]["to"] == "CERT-9281"


def test_hsm_and_kms_bindings_are_declared_edges_not_observations():
    body = tp.build(tp.from_hops([], [], [
        {"host": "Internal LB", "hsm_id": "HSM-1", "evidence_id": "HSM-E1",
         "observed_at": "2026-11-01T00:00:00Z"},
        {"host": "Internal LB", "kms_id": "KMS-1", "evidence_id": "KMS-E1",
         "observed_at": "2026-11-01T00:00:00Z"}])["claims"])
    kinds = {edge["kind"]: edge["confidence"] for edge in body["edges"]}
    assert kinds == {"USES_HSM": "DECLARED", "USES_KMS": "DECLARED"}


def test_the_audit_finds_a_terminal_that_was_read_as_the_application():
    body = tp.build([{**BASE, "kind": "TERMINATES_TLS", "from": "Internet",
                      "to": "Payments API"}],
                    nodes=[tp.node("Internet", role="LOAD_BALANCER"),
                           tp.node("Payments API", role="APPLICATION")])
    audit = tp.audit(body, applications=["payments api"])
    assert audit["counts"] == {"TLS_ATTRIBUTED_TO_AN_APPLICATION": 1}
    assert "not the application's property" in audit["findings"][0]["detail"]


def test_the_audit_finds_nodes_that_only_appear_because_an_edge_names_them():
    body = tp.build([{**BASE, "kind": "CONNECTS_TO", "from": "a", "to": "b"}],
                    nodes=[tp.node("a", role="LOAD_BALANCER")])
    audit = tp.audit(body)
    assert audit["counts"] == {"UNDECLARED_NODE": 1}
    assert audit["findings"][0]["node"] == "b"


def test_a_clean_topology_audits_clean_and_says_so():
    body = tp.build([{**BASE, "kind": "CONNECTS_TO", "from": "a", "to": "b"}],
                    nodes=[tp.node("a"), tp.node("b")])
    audit = tp.audit(body)
    assert audit["clean"] is True
    assert "internally honest" in audit["statement"]


def test_the_audit_refuses_a_document_that_is_not_a_topology():
    with pytest.raises(ValueError, match="not a"):
        tp.audit({"edges": []})


def test_a_node_needs_a_name():
    with pytest.raises(ValueError, match="needs a name"):
        tp.node("   ")
    assert tp.node("lb-1", role="load_balancer")["role"] == "LOAD_BALANCER"


def test_an_edge_needs_both_ends():
    body = tp.build([{**BASE, "kind": "CONNECTS_TO", "from": "a"}])
    assert "needs both ends" in body["refused"][0]["reason"]
    body = tp.build(["not a relationship"])
    assert "must be an object" in body["refused"][0]["reason"]


def test_unused_kinds_are_named_so_the_gap_is_visible():
    body = tp.build([{**BASE, "kind": "CONNECTS_TO", "from": "a", "to": "b"}])
    assert "RE_ENCRYPTS" in body["kinds_unused"] and "USES_HSM" in body["kinds_unused"]
    assert "CONNECTS_TO" not in body["kinds_unused"]


def test_the_summary_reports_the_observed_share_and_what_is_unproven():
    body = tp.build(tp.from_hops(HOPS, [{"endpoint": "External LB",
                                        "certificate_ref": "CERT-9281",
                                        "evidence_id": "CERT-E1",
                                        "observed_at": "2026-11-01T00:00:00Z"}])["claims"])
    summary = tp.summary(body)
    assert summary["relationships"] == 5
    assert summary["observed_share"] == 1.0
    assert summary["confidence"] == {"OBSERVED": 5, "ASSEMBLED": 0, "DECLARED": 0}
    assert any("permitted flow" in line for line in summary["not_proven"])


def test_the_topology_states_the_four_things_it_cannot_prove():
    assert len(tp.NOT_PROVEN) >= 4
    joined = " ".join(tp.NOT_PROVEN)
    assert "collected" in joined and "policy is consulted" in joined
    assert "packet capture" in joined
