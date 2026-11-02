"""A CBOM asset says what was observed, by whom, and what it may not claim."""

from __future__ import annotations

import pytest

from cbom import usage_evidence as ue

AES = {"algorithm": "AES-256-GCM", "parameters": {"key_size": 256, "mode": "GCM"},
       "purpose": "TLS"}


def _event(klass, *, evidence_id="EVID-1", algorithm="AES-256-GCM", layer=None, **extra):
    return {"class": klass, "evidence_id": evidence_id, "algorithm": algorithm,
            "layer": layer, **extra}


# --------------------------------------------------------------------------- #
# evidence classes and refusals


def test_the_vocabulary_is_the_reviews_nine_classes():
    assert ue.EVIDENCE_CLASSES == ("OBSERVED", "STATIC_OBSERVED", "RUNTIME_OBSERVED",
                                   "NETWORK_OBSERVED", "CONFIGURED", "IMPORTED",
                                   "VENDOR_DECLARED", "INFERRED", "UNKNOWN")


def test_an_imported_event_cannot_call_itself_an_observation():
    event = ue.normalize_event({"class": "IMPORTED", "layer": "runtime", "evidence_id": "E-1"})
    assert event["class"] == "IMPORTED" and event["observed"] is False
    assert event["downgrades"]


def test_an_observation_without_an_evidence_id_is_refused():
    with pytest.raises(ue.EvidenceRefused, match="evidence id"):
        ue.normalize_event({"class": "RUNTIME_OBSERVED"})


def test_an_unknown_class_is_refused_not_mapped_to_unknown():
    with pytest.raises(ue.EvidenceRefused):
        ue.normalize_event({"class": "PROBABLY"})


def test_a_layer_implies_its_class():
    assert ue.normalize_event({"layer": "runtime", "evidence_id": "E-1"})["class"] == \
        "RUNTIME_OBSERVED"
    assert ue.normalize_event({"layer": "sbom", "evidence_id": "E-1"})["class"] == "IMPORTED"


# --------------------------------------------------------------------------- #
# the usage profile


def test_capability_alone_is_a_candidate_never_usage():
    profile = ue.usage_profile(AES, [_event("IMPORTED")])
    assert profile["capability"] is True
    assert profile["usage"] == "CANDIDATE_ONLY"
    assert profile["confidence"] == "LOW"
    assert "capability and not an invocation" in profile["statement"]
    assert profile["layers"]["runtime"]["observed"] is False


def test_static_observation_is_medium():
    profile = ue.usage_profile(AES, [_event("STATIC_OBSERVED", evidence_id="STATIC-1")])
    assert (profile["usage"], profile["confidence"]) == ("OBSERVED", "MEDIUM")
    assert profile["layers"]["static"]["observed"] is True


def test_runtime_alone_is_high_and_names_the_evidence():
    profile = ue.usage_profile(AES, [_event("RUNTIME_OBSERVED", evidence_id="RUNTIME-92821")])
    assert profile["confidence"] == "HIGH"
    assert profile["evidence_ids"] == ["RUNTIME-92821"]
    assert profile["layers"]["runtime"]["evidence"] == ["RUNTIME-92821"]


def test_runtime_and_network_together_are_very_high():
    profile = ue.usage_profile(AES, [
        _event("RUNTIME_OBSERVED", evidence_id="RUNTIME-1"),
        _event("NETWORK_OBSERVED", evidence_id="NET-1"),
    ])
    assert profile["confidence"] == "VERY_HIGH"
    assert "independent collection mechanisms" in profile["confidence_reason"]


def test_the_four_layer_view_matches_the_review():
    profile = ue.usage_profile(AES, [
        _event("STATIC_OBSERVED", evidence_id="S-1"),
        _event("CONFIGURED", evidence_id="C-1"),
        _event("RUNTIME_OBSERVED", evidence_id="R-1"),
        _event("NETWORK_OBSERVED", evidence_id="N-1"),
    ])
    observed = {name: row["observed"] for name, row in profile["layers"].items()}
    assert observed == {"static": True, "config": True, "runtime": True, "network": True}
    assert profile["usage"] == "OBSERVED"


def test_evidence_about_another_algorithm_does_not_count():
    profile = ue.usage_profile(AES, [_event("RUNTIME_OBSERVED", algorithm="RSA-2048",
                                            evidence_id="R-9")])
    assert profile["usage"] == "NOT_OBSERVED" and profile["evidence_ids"] == []


def test_a_refused_event_is_reported_not_silently_dropped():
    profile = ue.usage_profile(AES, [_event("RUNTIME_OBSERVED", evidence_id=""),
                                     _event("STATIC_OBSERVED", evidence_id="S-1")])
    assert len(profile["refused"]) == 1
    assert profile["usage"] == "OBSERVED"


def test_an_empty_profile_reports_unknown_not_absent():
    profile = ue.usage_profile(AES, [])
    assert profile["usage"] == "NOT_OBSERVED"
    assert profile["confidence"] == "UNKNOWN"
    assert "no evidence has been collected" in profile["confidence_reason"]


def test_an_unknown_purpose_is_named_in_the_statement():
    profile = ue.usage_profile({**AES, "purpose": "VIBES"}, [_event("STATIC_OBSERVED")])
    assert "not a known purpose" in profile["statement"]


def test_purposes_are_a_closed_vocabulary():
    assert {"DATA_AT_REST", "PAYMENT_SIGNING", "HSM_OPERATION"} - set(ue.PURPOSES) == set()


# --------------------------------------------------------------------------- #
# capability is not invocation


def test_a_crypto_library_yields_candidates_never_used_assets():
    body = ue.capability_candidates("openssl", ["AES-256", "RSA-2048", "ECDSA-P256"],
                                    evidence_id="SBOM-1")
    assert {row["usage"] for row in body["candidates"]} == {"CANDIDATE_ONLY"}
    assert {row["confidence"] for row in body["candidates"]} == {"LOW"}
    assert "not an application that calls it" in body["statement"]
    assert body["promotable_by"] == ["STATIC_OBSERVED", "RUNTIME_OBSERVED", "NETWORK_OBSERVED"]


def test_a_candidate_stays_imported_when_it_came_from_an_sbom():
    body = ue.capability_candidates("openssl", ["AES-256"], source="sbom")
    assert body["candidates"][0]["evidence"][0]["class"] == "IMPORTED"


# --------------------------------------------------------------------------- #
# conflicts


def _claims(container="3.0.13", runtime="3.0.11"):
    return [
        {"field": "version", "fact": "3.0.13", "source": "sbom"},
        {"field": "version", "fact": container, "source": "container", "evidence_id": "C-1"},
        {"field": "version", "fact": runtime, "source": "runtime", "evidence_id": "R-1"},
    ]


def test_every_source_is_kept_including_the_imported_one():
    body = ue.reconcile(_claims())
    assert [row["class"] for row in body["rows"]] == ["IMPORTED", "OBSERVED",
                                                       "RUNTIME_OBSERVED"]


def test_disagreeing_observations_are_a_conflict_not_a_collapse():
    body = ue.reconcile(_claims())
    conflict = body["conflicts"][0]
    assert conflict["kind"] == "VERSION_CONFLICT"
    assert conflict["values"] == {"container": "3.0.13", "runtime": "3.0.11"}
    assert conflict["evidence"] == {"container": "C-1", "runtime": "R-1"}


def test_a_conflicted_field_asserts_no_value():
    body = ue.reconcile(_claims())
    assert body["resolved"][0]["value"] is None
    assert "no single value is asserted" in body["resolved"][0]["statement"]


def test_agreeing_observations_resolve_to_the_strongest_claim():
    body = ue.reconcile(_claims(container="3.0.13", runtime="3.0.13"))
    assert body["conflicts"] == []
    assert body["resolved"][0]["value"] == "3.0.13"
    assert body["resolved"][0]["basis"] == "RUNTIME_OBSERVED"


def test_an_imported_claim_alone_never_conflicts_with_an_observation():
    body = ue.reconcile([
        {"field": "version", "fact": "3.0.11", "source": "sbom"},
        {"field": "version", "fact": "3.0.13", "source": "runtime", "evidence_id": "R-1"},
    ])
    assert body["conflicts"] == []
    assert body["resolved"][0]["value"] == "3.0.13"
    assert body["resolved"][0]["basis"] == "RUNTIME_OBSERVED"


def test_a_claim_without_evidence_is_refused_by_reconcile():
    body = ue.reconcile([{"field": "version", "fact": "3.0.13", "source": "runtime"}])
    assert body["refused"] and body["rows"] == []


# --------------------------------------------------------------------------- #
# TLS hops


def _hop(endpoint, on, version, suite, evidence):
    return {"from": "client", "to": on, "endpoint": endpoint, "observed_on": on,
            "tls_version": version, "cipher_suite": suite, "evidence_id": evidence}


def test_tls_termination_is_three_relationships_not_one_attribute():
    body = ue.tls_paths([
        _hop("payments.bank.example:443", "External LB", "TLS1.3", "TLS_AES_256_GCM_SHA384", "NET-1"),
        _hop("10.0.0.5:443", "API Gateway", "TLS1.2", "TLS_ECDHE_RSA_AES_128_GCM_SHA256", "NET-2"),
        _hop("10.0.2.9:8443", "Payments API", "TLS1.3", "TLS_AES_256_GCM_SHA384", "NET-3"),
    ])
    assert len(body["paths"]) == 3
    assert [row["tls_version"] for row in body["paths"]] == ["TLS1.3", "TLS1.2", "TLS1.3"]
    assert {row["attributed_to"] for row in body["paths"]} == {
        "payments.bank.example:443", "10.0.0.5:443", "10.0.2.9:8443"}
    assert "not to the application behind it" in body["statement"]


def test_a_hop_without_an_endpoint_is_refused():
    body = ue.tls_paths([{"from": "client", "to": "lb", "evidence_id": "NET-1"}])
    assert body["paths"] == [] and body["refused"]


def test_a_hop_without_evidence_is_refused():
    body = ue.tls_paths([{"endpoint": "x:443", "evidence_id": ""}])
    assert body["refused"]


# --------------------------------------------------------------------------- #
# certificates, keys, HSM


def test_a_certificate_is_its_own_category_and_proves_no_operation():
    body = ue.certificate_evidence({
        "certificate_ref": "cert-9281", "public_key_algorithm": "ECDSA", "curve": "P-256",
        "signature_algorithm": "ECDSA-SHA256", "san": ["payments.bank.example"],
        "endpoint": "payments.bank.example:443", "observed_on": "External LB",
        "evidence_id": "CERT-1"})
    assert body["certificate"]["category"] == "CERTIFICATE"
    assert body["usage"] == "CERTIFICATE_ONLY"
    assert body["application_operation_proven"] is False
    assert "does not prove" in body["statement"]


def test_an_incomplete_certificate_names_what_is_missing():
    body = ue.certificate_evidence({"certificate_ref": "cert-1",
                                    "public_key_algorithm": "RSA"})
    assert body["incomplete"] == ["signature_algorithm", "evidence_id"]


def test_key_metadata_is_stored_without_material():
    body = ue.key_metadata({"key_ref": "HSM://partition-01/key/PAY-SIGN-001",
                            "algorithm": "RSA", "key_size": 2048, "purpose": "signature",
                            "provider": "hsm", "evidence_id": "HSM-EVID-001"})
    assert body["private_material"] == "NOT STORED"
    assert body["purpose"] == "SIGNATURE" and body["purpose_known"] is True


def test_a_private_key_in_a_cbom_is_an_error():
    with pytest.raises(ue.EvidenceRefused, match="never key material"):
        ue.key_metadata({"key_ref": "k1", "private_key_pem": "-----BEGIN PRIVATE KEY-----"})


def test_an_unexpected_key_field_is_refused():
    with pytest.raises(ue.EvidenceRefused, match="unexpected key metadata"):
        ue.key_metadata({"key_ref": "k1", "whatever": "x"})


def test_a_key_record_needs_a_reference():
    with pytest.raises(ue.EvidenceRefused, match="key_ref"):
        ue.key_metadata({"algorithm": "RSA"})


def test_hsm_capability_configured_key_and_operation_are_three_answers():
    capability = ue.hsm_evidence("CAPABILITY")
    configured = ue.hsm_evidence("CONFIGURED_KEY", evidence_id="HSM-EVID-002")
    operation = ue.hsm_evidence("OPERATION", evidence_id="HSM-EVID-003", operation="sign")
    assert (capability["class"], capability["observed"]) == ("VENDOR_DECLARED", False)
    assert (configured["class"], configured["observed"]) == ("CONFIGURED", True)
    assert (operation["class"], operation["observed"]) == ("RUNTIME_OBSERVED", True)
    assert operation["operation"] == "SIGN"


def test_an_hsm_operation_without_evidence_is_refused():
    with pytest.raises(ue.EvidenceRefused):
        ue.hsm_evidence("OPERATION")


def test_an_unknown_hsm_kind_is_refused():
    with pytest.raises(ue.EvidenceRefused):
        ue.hsm_evidence("SUPPORTED")


# --------------------------------------------------------------------------- #
# coverage


def test_partial_coverage_does_not_let_the_count_be_quoted_as_a_total():
    body = ue.coverage(100, 62, 12)
    assert (body["coverage_pct"], body["completeness"]) == (62.0, "PARTIAL")
    assert body["quotable_as_total"] is False
    assert body["statement"].startswith("12 crypto asset(s) discovered; 62/100 application(s)")
    assert "not what exists" in body["statement"]


def test_full_coverage_is_the_only_total():
    body = ue.coverage(100, 100, 12)
    assert body["completeness"] == "COMPLETE" and body["quotable_as_total"] is True


def test_a_never_inspected_estate_reports_none_not_zero():
    body = ue.coverage(100, 0, 0)
    assert body["completeness"] == "NONE" and body["coverage_pct"] == 0.0


def test_an_estate_with_no_systems_is_unknown():
    assert ue.coverage(0, 0, 0)["completeness"] == "UNKNOWN"
