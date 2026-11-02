"""Adversarial CBOM: the review's five security blockers, attacked on purpose.

Item 21 of the review lists five red items:

1. **evidence spoofing** — imported CBOM/SBOM/vendor data must never become
   ``OBSERVED`` on its own say-so;
2. **false crypto attribution** — a library must not become every algorithm it
   supports;
3. **weak evidence promotion** — ``VENDOR_DECLARED`` must not become
   ``RUNTIME_OBSERVED``;
4. **secret leakage** — collectors store references and properties, never
   material;
5. **signature/hash confusion** — a hash, an HMAC and a signature are different
   contracts.

These tests take the attacker's side. Each one hands the pipeline the most
convenient possible input and asserts that it is *not* believed — and, where the
answer is a downgrade, that the downgrade is recorded rather than silent.
"""

from __future__ import annotations

import pytest

from cbom import estate_chain as ec
from cbom import pqc_handoff as pq
from cbom import promotion as promo
from cbom import usage_collectors as uc
from cbom import usage_evidence as ue

AES = "AES-256-GCM"


def _spoof(**overrides):
    return {**{"class": "RUNTIME_OBSERVED", "evidence_id": "VENDOR-1",
               "algorithm": AES}, **overrides}


# --------------------------------------------------------------------------- #
# 1. evidence spoofing


@pytest.mark.parametrize("origin", ["imported", "import", "upload", "document",
                                    "cyclonedx", "spdx", "sbom"])
def test_an_imported_origin_can_never_call_itself_an_observation(origin):
    event = ue.normalize_event(_spoof(layer=origin))
    assert event["class"] == "IMPORTED"
    assert event["observed"] is False
    assert event["downgrades"]


@pytest.mark.parametrize("origin", ["vendor", "vendor_declaration"])
def test_a_vendor_origin_is_downgraded_to_a_declaration(origin):
    event = ue.normalize_event(_spoof(source=origin))
    assert event["class"] == "VENDOR_DECLARED"
    assert event["observed"] is False


@pytest.mark.parametrize("claimed", ["OBSERVED", "RUNTIME_OBSERVED",
                                     "NETWORK_OBSERVED", "STATIC_OBSERVED",
                                     "CONFIGURED"])
def test_no_observing_class_survives_an_imported_origin(claimed):
    event = ue.normalize_event({"class": claimed, "layer": "imported",
                                "evidence_id": "V-1"})
    assert event["class"] == "IMPORTED"
    assert event["observed"] is False


def test_the_downgrade_is_recorded_not_silent():
    event = ue.normalize_event(_spoof(layer="sbom"))
    assert "origin is sbom (IMPORTED)" in event["downgrades"][0]
    assert "weaker class is kept" in event["downgrades"][0]


def test_an_evidence_id_does_not_launder_an_imported_source():
    event = ue.normalize_event(_spoof(layer="imported", evidence_id="PERFECT-LOOKING-ID"))
    assert event["class"] == "IMPORTED" and event["observed"] is False


def test_a_genuinely_observing_origin_keeps_the_claim_it_makes():
    """The guard is about the *origin* an event names, not about the class string.

    ``container`` is an observing layer of this platform (the image was scanned),
    so a runtime claim from it is not an imported document talking: the caller owns
    the evidence id and the claim. The boundary is stated in the guide rather than
    hidden behind a guess.
    """
    event = ue.normalize_event(_spoof(layer="container"))
    assert event["class"] == "RUNTIME_OBSERVED"
    assert event["downgrades"] == []


def test_a_real_runtime_event_is_not_downgraded():
    """The guard must not break the collector it exists to protect."""
    event = ue.normalize_event({"layer": "runtime", "evidence_id": "R-1",
                                "algorithm": AES})
    assert event["class"] == "RUNTIME_OBSERVED" and event["observed"] is True
    assert event["downgrades"] == []


def test_a_spoofed_event_cannot_promote_a_capability():
    promoted = promo.promote(
        [{"name": "openssl", "evidence_id": "SBOM-1", "algorithms": [AES]}],
        [_spoof(layer="imported")])
    assert promoted["assets"] == []
    assert [row["algorithm"] for row in promoted["candidates"]] == [AES]


def test_a_spoofed_event_leaves_the_usage_profile_a_candidate():
    profile = ue.usage_profile({"algorithm": AES}, [_spoof(layer="imported")])
    assert profile["usage"] == "CANDIDATE_ONLY"
    assert profile["confidence"] == "LOW"


def test_the_estate_chain_does_not_promote_a_spoofed_import():
    result = ec.run({"name": "spoofed",
                     "components": [{"name": "openssl", "evidence_id": "SBOM-1",
                                     "algorithms": [AES]}],
                     "imported_events": [_spoof(layer="imported")]})
    assert result["document"]["components"] == []


# --------------------------------------------------------------------------- #
# 2. false crypto attribution


def test_a_library_never_becomes_every_algorithm_it_supports():
    promoted = promo.promote([{"name": "openssl", "evidence_id": "SBOM-1",
                               "algorithms": ["AES-128-GCM", "AES-256-GCM",
                                              "RSA-2048", "ECDSA-P256"]}], [])
    assert promoted["assets"] == []
    assert len(promoted["candidates"]) == 4
    assert all(row["profile"]["usage"] in {"NOT_OBSERVED", "CANDIDATE_ONLY"}
               for row in promoted["candidates"])
    assert all(row["profile"]["usage"] != "OBSERVED" for row in promoted["candidates"])


def test_a_capability_only_estate_produces_an_empty_document_not_a_full_one():
    result = ec.run({"name": "capabilities",
                     "components": [{"name": "openssl", "evidence_id": "SBOM-1",
                                     "algorithms": ["AES-256-GCM", "RSA-2048"]}]})
    assert result["document"]["components"] == []
    assert result["promotion"]["candidates"]


def test_a_component_with_no_evidence_id_contributes_nothing():
    promoted = promo.promote([{"name": "openssl", "algorithms": ["AES-256-GCM"]}], [])
    assert promoted["assets"] == [] and promoted["candidates"] == []
    assert "no evidence id" in promoted["refused"][0]["reason"]


# --------------------------------------------------------------------------- #
# 3. weak evidence promotion


def test_a_vendor_declaration_never_reaches_runtime():
    promoted = promo.promote(
        [{"name": "openssl", "evidence_id": "SBOM-1", "algorithms": [AES]}],
        [{"layer": "vendor", "evidence_id": "V-1", "algorithm": AES}])
    assert promoted["assets"] == []
    assert promoted["candidates"][0]["profile"]["usage"] == "CANDIDATE_ONLY"


def test_a_vendor_claim_about_quantum_readiness_is_ignored():
    """A vendor document can say anything; the handoff classifies the algorithm."""
    rows = pq.handoff([{"algorithm": "RSA-2048", "key_size": 2048,
                        "usage": "RUNTIME", "quantum_status": "POST_QUANTUM",
                        "quantum_safe": True, "evidence_ids": ["V-1"]}])["rows"]
    assert rows[0]["quantum_status"] == "QUANTUM_SENSITIVE"
    assert rows[0]["status_basis"] == "REGISTRY_SHOR"


def test_an_unattributed_observation_is_refused_rather_than_promoted():
    promoted = promo.promote(
        [{"name": "openssl", "evidence_id": "SBOM-1", "algorithms": [AES]}],
        [{"class": "RUNTIME_OBSERVED", "algorithm": AES}])
    assert promoted["assets"] == []
    assert promoted["candidates"]


# --------------------------------------------------------------------------- #
# 4. secret leakage


@pytest.mark.parametrize("field", ["private_key", "secret", "secret_key",
                                   "session_key", "plaintext", "payload",
                                   "customer_payload", "password"])
def test_a_key_record_carrying_material_is_refused(field):
    with pytest.raises(ue.EvidenceRefused) as refusal:
        ue.key_metadata({"key_ref": "HSM://partition-01/key/PAY-SIGN-001",
                         field: "do-not-store-me"})
    assert field in str(refusal.value)


def test_key_metadata_keeps_references_and_states_that_nothing_is_stored():
    record = ue.key_metadata({
        "key_ref": "HSM://partition-01/key/PAY-SIGN-001", "algorithm": "RSA",
        "key_size": 2048, "purpose": "SIGNATURE", "status": "ENABLED",
        "location": "partition-01", "owner": "payments", "evidence_id": "HSM-1"})
    assert record["private_material"] == "NOT STORED"
    # the record is metadata: the only "material" word in it is the refusal to store
    assert "do-not-store-me" not in str(record)


def test_the_estate_chain_refuses_a_key_record_with_material():
    result = ec.run({"name": "leaky",
                     "keys": [{"key_ref": "k/1", "algorithm": "RSA", "key_size": 2048,
                               "provider": "AWS_KMS", "status": "ENABLED",
                               "evidence_id": "KMS-1", "private_key": "MIIEv..."}]})
    assert result["keys"]["refused"]
    assert "MIIEv" not in str(result["document"])


# --------------------------------------------------------------------------- #
# 5. signature / hash confusion


def test_a_certificate_is_its_own_evidence_category():
    certificate = ue.certificate_evidence({
        "certificate_ref": "cert-9281", "public_key_algorithm": "ECDSA",
        "curve": "P-256", "signature_algorithm": "ECDSA-SHA256",
        "endpoint": "payments.bank.example:443", "observed_on": "External LB",
        "evidence_id": "NET-9281"})
    assert certificate["usage"] == "CERTIFICATE_ONLY"
    assert certificate["certificate"]["public_key_algorithm"] == "ECDSA"
    assert certificate["application_operation_proven"] is False
    assert "does not prove" in certificate["statement"]


def test_a_certificate_never_promotes_the_application_to_ecdsa():
    promoted = promo.promote(
        [{"name": "openssl", "evidence_id": "SBOM-1", "algorithms": ["ECDSA-P256"]}],
        [ue.certificate_evidence({
            "certificate_ref": "cert-9281", "public_key_algorithm": "ECDSA",
            "curve": "P-256", "signature_algorithm": "ECDSA-SHA256",
            "evidence_id": "NET-9281"})])
    assert promoted["assets"] == []


def test_a_suite_says_which_algorithm_plays_which_role():
    facts = {fact["algorithm"]: fact["role"]
             for fact in uc.algorithms_from_cipher_suite("ECDHE-RSA-AES256-GCM-SHA384")}
    assert facts["AES-256-GCM"] == "BULK"
    assert facts["RSA"] == "SIGNATURE"
    assert facts["ECDHE"] == "KEY_EXCHANGE"
    assert facts["SHA-384"] == "HASH"


def test_a_hash_is_never_counted_as_a_signature():
    facts = {fact["algorithm"]: fact["role"]
             for fact in uc.algorithms_from_cipher_suite("TLS_AES_256_GCM_SHA384")}
    assert facts["SHA-384"] == "HASH"
    assert "SIGNATURE" not in set(facts.values())


def test_an_unknown_algorithm_gets_no_role_rather_than_a_guess():
    assert uc.algorithms_from_cipher_suite("TLS_NONSENSE_XYZ") == []
