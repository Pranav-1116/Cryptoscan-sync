"""Review item 9: endpoint → certificate → key → signature → issuer → trust chain."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from cbom import certificate_chain as cc

NOW = datetime(2026, 11, 3, tzinfo=timezone.utc)

LEAF = {
    "certificate_ref": "CERT-9281", "subject": "CN=payments.bank.example",
    "issuer": "CN=BANK-ICA-01", "serial": "0A1B2C",
    "fingerprint_sha256": "aa11bb22cc33dd44",
    "san": ["payments.bank.example", "payments"], "not_before": "2026-01-01T00:00:00Z",
    "not_after": "2027-01-01T00:00:00Z", "public_key_algorithm": "ECDSA",
    "key_size": 256, "curve": "P-256", "signature_algorithm": "ECDSA-SHA256",
    "authority_key_id": "ski-ica", "endpoint": "payments.bank.example:443",
    "evidence_id": "CERT-E1", "source": "network-probe",
    "observed_at": "2026-11-01T00:00:00Z",
}
INTERMEDIATE = {
    "certificate_ref": "CERT-ICA1", "subject": "CN=BANK-ICA-01",
    "issuer": "CN=BANK-ROOT-01", "is_ca": True, "not_before": "2020-01-01T00:00:00Z",
    "not_after": "2030-01-01T00:00:00Z", "public_key_algorithm": "RSA", "key_size": 4096,
    "signature_algorithm": "SHA256-RSA", "subject_key_id": "ski-ica",
    "evidence_id": "CERT-E2", "source": "pki-export",
}
ROOT = {
    "certificate_ref": "CERT-ROOT", "subject": "CN=BANK-ROOT-01",
    "issuer": "CN=BANK-ROOT-01", "is_ca": True, "not_after": "2035-01-01T00:00:00Z",
    "public_key_algorithm": "RSA", "key_size": 4096, "signature_algorithm": "SHA256-RSA",
    "evidence_id": "CERT-E3", "source": "pki-export",
}


def test_one_certificate_carries_every_hop_the_review_names():
    body = cc.certificate(LEAF, now=NOW)
    assert body["certificate_ref"] == "CERT-9281"
    assert body["endpoints"] == ["payments.bank.example:443"]
    assert body["public_key"] == {"algorithm": "ECDSA", "key_size": 256, "curve": "P-256",
                                  "quantum_vulnerable": True}
    assert body["signature_algorithm"] == "ECDSA-SHA256"
    assert body["issuer"] == "CN=BANK-ICA-01"
    assert body["san"] == ["payments", "payments.bank.example"]
    assert body["state"] == "VALID" and body["days_to_expiry"] > 0
    assert body["revocation"] == "UNKNOWN"
    assert body["private_material"] == "NOT_STORED"


def test_a_certificate_with_no_reference_is_refused():
    with pytest.raises(ValueError, match="needs a reference"):
        cc.certificate({"subject": "CN=x", "evidence_id": "E"})
    fingerprint_only = cc.certificate({"fingerprint_sha256": "abcdef0123456789",
                                       "evidence_id": "E"}, now=NOW)
    assert fingerprint_only["certificate_ref"] == "CERT-ABCDEF012345"


def test_a_certificate_with_no_evidence_is_refused():
    with pytest.raises(ValueError, match="no evidence id"):
        cc.certificate({"certificate_ref": "CERT-1", "subject": "CN=x"}, now=NOW)


def test_the_chain_is_assembled_leaf_to_root():
    body = cc.chain([LEAF, INTERMEDIATE, ROOT], anchors=["CERT-ROOT"], now=NOW)
    leaf = next(path for path in body["paths"] if path["certificate_ref"] == "CERT-9281")
    assert leaf["position"] == "LEAF" and leaf["resolution"] == "ANCHORED"
    assert leaf["path"][1]["certificate_ref"] == "CERT-ICA1"
    assert leaf["path"][2]["certificate_ref"] == "CERT-ROOT"
    assert leaf["depth"] == 3 and leaf["anchor"] == "CERT-ROOT"
    assert body["resolutions"] == {"ANCHORED": 3}
    assert "no signature was verified" in body["statement"]


def test_the_issuer_is_matched_by_key_id_before_name():
    body = cc.chain([LEAF, INTERMEDIATE, ROOT], now=NOW)
    leaf = next(path for path in body["paths"] if path["certificate_ref"] == "CERT-9281")
    assert leaf["matched_by"][0] == "AUTHORITY_KEY_ID"
    intermediate = next(path for path in body["paths"]
                        if path["certificate_ref"] == "CERT-ICA1")
    assert intermediate["matched_by"] == ["ISSUER_NAME"]


def test_an_issuer_that_is_not_in_the_inventory_is_a_hole_not_a_root():
    body = cc.chain([LEAF], now=NOW)
    path = body["paths"][0]
    assert path["resolution"] == "INCOMPLETE"
    assert path["missing_issuer"] == "CN=BANK-ICA-01"
    assert "is not in the inventory" in path["statement"]
    assert body["anchors_unconfirmed"] == []


def test_a_self_signed_root_that_nobody_declared_is_an_unconfirmed_anchor():
    body = cc.chain([LEAF, INTERMEDIATE, ROOT], now=NOW)
    assert body["resolutions"] == {"ANCHORED": 3}
    assert body["anchors_unconfirmed"] == ["CERT-ROOT"]
    declared = cc.chain([LEAF, INTERMEDIATE, ROOT], anchors=["CERT-ROOT"], now=NOW)
    assert declared["anchors_unconfirmed"] == []


def test_an_ambiguous_issuer_name_is_a_loop_and_never_a_coin_flip():
    # with no authority key id, two certificates share the leaf's issuer name
    twin_ica = {**INTERMEDIATE, "certificate_ref": "CERT-ICA2",
                "fingerprint_sha256": "ffff", "subject_key_id": "ski-ica-2"}
    leafless = {key: value for key, value in LEAF.items() if key != "authority_key_id"}
    body = cc.chain([leafless, INTERMEDIATE, twin_ica], now=NOW)
    leaf = next(path for path in body["paths"] if path["certificate_ref"] == "CERT-9281")
    assert leaf["resolution"] == "LOOP"
    assert leaf["depth"] == 1


def test_a_key_id_settles_an_issuer_name_two_certificates_share():
    twin_ica = {**INTERMEDIATE, "certificate_ref": "CERT-ICA2",
                "fingerprint_sha256": "ffff", "subject_key_id": "ski-ica-2"}
    body = cc.chain([LEAF, INTERMEDIATE, twin_ica, ROOT], anchors=["CERT-ROOT"], now=NOW)
    leaf = next(path for path in body["paths"] if path["certificate_ref"] == "CERT-9281")
    assert leaf["resolution"] == "ANCHORED"
    assert leaf["matched_by"][0] == "AUTHORITY_KEY_ID"


def test_a_declared_edge_can_supply_the_parent():
    body = cc.chain([LEAF, INTERMEDIATE, ROOT],
                    declared={"CERT-9281": "CERT-ICA1"}, now=NOW)
    leaf = next(path for path in body["paths"] if path["certificate_ref"] == "CERT-9281")
    assert leaf["resolution"] == "ANCHORED"


def test_the_chain_reports_expiry_as_a_state_not_a_boolean():
    expired = {**LEAF, "certificate_ref": "CERT-OLD", "not_after": "2026-01-01T00:00:00Z",
               "not_before": "2025-01-01T00:00:00Z"}
    soon = {**LEAF, "certificate_ref": "CERT-SOON", "not_after": "2026-11-20T00:00:00Z"}
    future = {**LEAF, "certificate_ref": "CERT-LATER",
              "not_before": "2027-01-01T00:00:00Z", "not_after": "2028-01-01T00:00:00Z"}
    body = cc.chain([expired, soon, future], now=NOW)
    states = {row["certificate_ref"]: row["state"] for row in body["certificates"].values()}
    assert states == {"CERT-OLD": "EXPIRED", "CERT-SOON": "EXPIRING",
                      "CERT-LATER": "NOT_YET_VALID"}
    assert body["states"] == {"EXPIRED": 1, "EXPIRING": 1, "NOT_YET_VALID": 1}


def test_a_missing_expiry_is_unknown_and_not_a_pass():
    body = cc.certificate({**LEAF, "not_after": None}, now=NOW)
    assert body["state"] == "UNKNOWN" and body["days_to_expiry"] is None
    assert "collection gap" in body["state_note"]


def test_a_weak_key_and_a_sha1_signature_are_reported_per_certificate():
    weak = {**LEAF, "certificate_ref": "CERT-WEAK", "public_key_algorithm": "RSA",
            "key_size": 1024, "signature_algorithm": "SHA1-RSA"}
    body = cc.certificate(weak, now=NOW)
    kinds = {problem["kind"] for problem in body["problems"]}
    assert {"WEAK_KEY", "WEAK_SIGNATURE", "QUANTUM_VULNERABLE"} <= kinds


def test_a_quantum_vulnerable_key_is_flagged_without_a_migration_verdict():
    body = cc.certificate(LEAF, now=NOW)
    kinds = {problem["kind"] for problem in body["problems"]}
    assert kinds == {"QUANTUM_VULNERABLE"}
    assert all("Shor" in problem["detail"] for problem in body["problems"]
               if problem["kind"] == "QUANTUM_VULNERABLE")


def test_paths_aggregate_the_problems_of_every_hop():
    weak_root = {**ROOT, "key_size": 1024, "signature_algorithm": "SHA1-RSA"}
    body = cc.chain([LEAF, INTERMEDIATE, weak_root], now=NOW)
    leaf = next(path for path in body["paths"] if path["certificate_ref"] == "CERT-9281")
    kinds = {problem["kind"] for problem in leaf["problems"]}
    assert {"WEAK_KEY", "WEAK_SIGNATURE"} <= kinds


def test_a_shared_public_key_between_certificates_is_reported():
    copy = {**LEAF, "certificate_ref": "CERT-9281-COPY", "subject": "CN=other.example",
            "issuer": "CN=BANK-ICA-01"}
    body = cc.chain([LEAF, copy, INTERMEDIATE, ROOT], now=NOW)
    assert body["shared_public_keys"] == {"aa11bb22cc33dd44":
                                          ["CERT-9281", "CERT-9281-COPY"]}


def test_the_chain_refuses_two_things_that_are_not_certificates():
    body = cc.chain([LEAF, "not a certificate", {"certificate_ref": "CERT-X"}], now=NOW)
    assert len(body["refused"]) == 2
    assert "must be an object" in body["refused"][0]["reason"]


def test_edges_carry_evidence_source_and_confidence():
    body = cc.chain([LEAF, INTERMEDIATE, ROOT], anchors=["CERT-ROOT"], now=NOW)
    edges = cc.edges(body)
    uses = [edge for edge in edges["edges"] if edge["kind"] == "USES_CERTIFICATE"]
    assert uses and uses[0]["from"] == "payments.bank.example:443"
    assert uses[0]["to"] == "CERT-9281"
    assert uses[0]["evidence_id"] == "CERT-E1"
    assert uses[0]["source"] == "network-probe"
    assert uses[0]["observed_at"] == "2026-11-01T00:00:00Z"
    assert uses[0]["confidence"] == "OBSERVED"
    signed = [edge for edge in edges["edges"] if edge["kind"] == "SIGNED_BY"]
    assert signed[0]["confidence"] == "ASSEMBLED"
    assert "not verified" in signed[0]["detail"]
    assert edges["counts"] == {"USES_CERTIFICATE": 1, "SIGNED_BY": 2}


def test_an_edge_with_no_evidence_is_not_written():
    body = cc.chain([{**LEAF, "evidence_id": "CERT-E1"}], now=NOW)
    edges = cc.edges(body)
    assert edges["edges"] and all(edge["evidence_id"] for edge in edges["edges"])


def test_a_presentation_with_no_observation_time_is_not_written():
    body = cc.chain([{**LEAF, "observed_at": None}, INTERMEDIATE, ROOT],
                    anchors=["CERT-ROOT"], now=NOW)
    edges = cc.edges(body)
    kinds = {row["confidence"] for row in edges["refused"]}
    assert "UNTIMED" in kinds
    assert not [edge for edge in edges["edges"]
                if edge["from"] == "payments.bank.example:443"]
    assert "no observation time" in edges["statement"]


def test_a_missing_issuer_becomes_a_hole_not_an_edge():
    body = cc.chain([LEAF], now=NOW)
    edges = cc.edges(body)
    absent = [row for row in edges["refused"] if row["confidence"] == "ABSENT"]
    assert absent[0]["to"] == "CN=BANK-ICA-01"
    assert "hole" in edges["statement"]


def test_edges_refuse_a_document_that_is_not_a_chain():
    with pytest.raises(ValueError, match="not a"):
        cc.edges({"paths": []})


def test_the_summary_names_expiry_weakness_and_quantum_exposure():
    body = cc.chain([LEAF, INTERMEDIATE, ROOT], anchors=["CERT-ROOT"], now=NOW)
    summary = cc.summary(body)
    assert summary["certificates"] == 3 and summary["paths"] == 3
    assert summary["anchored"] == ["CERT-9281", "CERT-ICA1", "CERT-ROOT"]
    assert summary["quantum_vulnerable"] == ["CERT-9281", "CERT-ICA1", "CERT-ROOT"]
    assert summary["expiring"] == []
    assert any("verifies no signature" in line for line in summary["not_proven"])


def test_names_are_compared_case_insensitively_and_in_component_order():
    lower = {**LEAF, "issuer": "cn=bank-ica-01"}
    body = cc.chain([lower, {**INTERMEDIATE, "subject": "cn=BANK-ica-01"}, ROOT],
                    anchors=["CERT-ROOT"], now=NOW)
    leaf = next(path for path in body["paths"] if path["certificate_ref"] == "CERT-9281")
    assert leaf["resolution"] == "ANCHORED"


def test_a_self_signed_leaf_is_not_a_root():
    alone = {**LEAF, "issuer": LEAF["subject"], "self_signed": True, "is_ca": False}
    body = cc.chain([alone], now=NOW)
    assert body["paths"][0]["resolution"] == "UNRESOLVED"
    assert body["paths"][0]["anchor"] is None
