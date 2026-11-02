"""Supported, configured, negotiated: three states, three evidences.

Review item 7's example is the fixture: supported TLS 1.2 and 1.3, configured
"TLS 1.2+", negotiated TLS 1.3 — and none of the three may be read as another.
"""

from __future__ import annotations

import pytest

from cbom import tls_state as ts

PAYMENTS = "payments.bank.example:443"

ROWS = [
    {"endpoint": PAYMENTS, "state": "NEGOTIATED", "tls_version": "1.3",
     "cipher_suite": "TLS_AES_256_GCM_SHA384", "group": "X25519",
     "signature_algorithm": "ECDSA-P256", "evidence_id": "NET-1",
     "observed_at": "2026-11-02T10:00:00Z"},
    {"endpoint": PAYMENTS, "state": "SUPPORTED", "tls_version": "1.3",
     "evidence_id": "ENUM-1", "enumeration_complete": True},
    {"endpoint": PAYMENTS, "state": "SUPPORTED", "tls_version": "1.2",
     "cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384", "evidence_id": "ENUM-1",
     "enumeration_complete": True},
    {"endpoint": PAYMENTS, "state": "CONFIGURED", "tls_version": "1.2",
     "evidence_id": "CFG-1"},
]


def _result(*rows):
    return ts.observe(rows or ROWS)


def _endpoint(result, endpoint=PAYMENTS):
    return {item["endpoint"]: item for item in result["endpoints"]}[endpoint]


# --------------------------------------------------------------------------- #
# version vocabulary


@pytest.mark.parametrize("raw,expected", [
    ("1.3", "TLS1.3"), ("TLSv1.2", "TLS1.2"), ("TLS1.2", "TLS1.2"),
    ("tls1_2", "TLS1.2"), ("TLS 1.1", "TLS1.1"), ("SSL3", "SSL3"), ("1.0", "TLS1.0"),
])
def test_a_protocol_name_is_normalised_once(raw, expected):
    assert ts._version(raw) == expected


def test_an_unrecognisable_protocol_is_left_as_it_arrived():
    assert ts._version("PQ-TLS-1") == "PQ-TLS-1"


# --------------------------------------------------------------------------- #
# the three states


def test_the_review_example_keeps_three_states_apart():
    item = _endpoint(_result())
    assert item["supported"]["versions"] == ["TLS1.2", "TLS1.3"]
    assert item["configured"]["versions"] == ["TLS1.2"]
    assert item["negotiated"]["versions"] == ["TLS1.3"]


def test_each_state_carries_its_own_evidence_ids():
    item = _endpoint(_result())
    assert item["supported"]["evidence_ids"] == ["ENUM-1"]
    assert item["configured"]["evidence_ids"] == ["CFG-1"]
    assert item["negotiated"]["evidence_ids"] == ["NET-1"]


def test_the_statement_names_all_three_rather_than_one_version():
    statement = _endpoint(_result())["statement"]
    assert "supported TLS1.2, TLS1.3" in statement
    assert "configured TLS1.2" in statement
    assert "negotiated TLS1.3" in statement


def test_negotiated_facets_are_kept_with_the_handshake_not_the_offer():
    item = _endpoint(_result())
    assert item["negotiated"]["groups"] == ["X25519"]
    assert item["negotiated"]["signature_algorithms"] == ["ECDSA-P256"]
    assert item["negotiated"]["observed_at"] == ["2026-11-02T10:00:00Z"]
    assert item["supported"]["groups"] == []


def test_aliases_are_accepted_but_never_mixed_up():
    result = _result({"endpoint": "ssh:22", "state": "ADVERTISED",
                      "cipher_suite": "chacha20-poly1305@openssh.com",
                      "evidence_id": "SSH-1"},
                     {"endpoint": "ssh:22", "state": "SELECTED",
                      "cipher_suite": "chacha20-poly1305@openssh.com",
                      "evidence_id": "SSH-2"})
    item = _endpoint(result, "ssh:22")
    assert item["supported"]["suites"] == ["chacha20-poly1305@openssh.com"]
    assert item["negotiated"]["suites"] == ["chacha20-poly1305@openssh.com"]
    assert item["supported"]["evidence_ids"] == ["SSH-1"]
    assert item["negotiated"]["evidence_ids"] == ["SSH-2"]


def test_configured_in_a_document_is_the_same_state_as_policy():
    result = _result({"endpoint": "a:443", "state": "ENABLED", "tls_version": "1.3",
                      "evidence_id": "CFG-9"})
    assert _endpoint(result, "a:443")["configured"]["versions"] == ["TLS1.3"]


# --------------------------------------------------------------------------- #
# refusals


def test_a_fact_whose_state_is_unknown_is_refused():
    result = _result({"endpoint": "a:443", "state": "MAYBE", "tls_version": "1.3",
                      "evidence_id": "X-1"})
    assert result["endpoints"] == []
    assert "cannot be sorted into one" in result["refused"][0]["reason"]


def test_a_fact_with_no_state_is_refused():
    result = _result({"endpoint": "a:443", "tls_version": "1.3", "evidence_id": "X-1"})
    assert "is not one of SUPPORTED" in result["refused"][0]["reason"]


def test_a_state_with_no_evidence_id_is_refused():
    result = _result({"endpoint": "a:443", "state": "SUPPORTED", "tls_version": "1.3"})
    assert result["refused"][0]["state"] == "SUPPORTED"
    assert "must be provable, not asserted" in result["refused"][0]["reason"]


def test_a_fact_about_no_facet_is_refused():
    result = _result({"endpoint": "a:443", "state": "NEGOTIATED", "evidence_id": "N-1"})
    assert "says nothing about the endpoint" in result["refused"][0]["reason"]


def test_an_observation_with_no_endpoint_is_refused():
    result = _result({"state": "NEGOTIATED", "tls_version": "1.3",
                      "evidence_id": "N-1"})
    assert result["refused"][0]["reason"] == "an observation needs an endpoint"


def test_a_row_that_is_not_an_object_is_refused():
    result = _result("payments:443")
    assert result["refused"][0]["reason"] == "an observation must be an object"


# --------------------------------------------------------------------------- #
# a negotiated handshake is not an enumeration


def test_negotiated_alone_cannot_prove_a_protocol_is_disabled():
    result = _result({"endpoint": "legacy:443", "state": "NEGOTIATED",
                      "tls_version": "1.2", "evidence_id": "NET-2"})
    verdict = ts.disabled(result, endpoint="legacy:443", version="1.1")
    assert verdict["proven"] is False
    assert verdict["state"] == "NOT_ENUMERATED"
    assert "a modern handshake is not an enumeration" in verdict["statement"]


def test_a_complete_enumeration_proves_absence():
    verdict = ts.disabled(_result(), endpoint=PAYMENTS, version="1.1")
    assert verdict["state"] == "DISABLED_PROVEN" and verdict["proven"] is True
    assert verdict["evidence_ids"] == ["ENUM-1", "NET-1"]


def test_an_incomplete_enumeration_cannot_prove_absence():
    result = _result({"endpoint": "a:443", "state": "SUPPORTED", "tls_version": "1.3",
                      "evidence_id": "ENUM-2", "enumeration_complete": False},
                     {"endpoint": "a:443", "state": "NEGOTIATED", "tls_version": "1.3",
                      "evidence_id": "NET-3"})
    verdict = ts.disabled(result, endpoint="a:443", version="1.2")
    assert verdict["state"] == "ENUMERATION_INCOMPLETE"
    assert "never asked about" in verdict["statement"]


def test_a_supported_protocol_is_not_disabled():
    verdict = ts.disabled(_result(), endpoint=PAYMENTS, version="1.2")
    assert verdict["state"] == "SUPPORTED" and verdict["proven"] is False


def test_a_negotiated_protocol_is_not_disabled():
    verdict = ts.disabled(_result(), endpoint=PAYMENTS, version="1.3")
    assert verdict["state"] == "IN_USE"


def test_an_endpoint_nobody_observed_is_unknown_not_clean():
    verdict = ts.disabled(_result(), endpoint="ghost:443", version="1.1")
    assert verdict["state"] == "UNKNOWN" and verdict["proven"] is False


# --------------------------------------------------------------------------- #
# the minimum, and what may be claimed from it


def test_configuration_is_the_first_basis_for_a_minimum():
    verdict = ts.minimum(_result(), endpoint=PAYMENTS)
    assert verdict["version"] == "TLS1.2"
    assert verdict["basis"] == "CONFIGURED"
    assert verdict["claimable"] is True


def test_a_complete_enumeration_is_the_second_basis():
    result = _result({"endpoint": "a:443", "state": "SUPPORTED", "tls_version": "1.3",
                      "evidence_id": "ENUM-3", "enumeration_complete": True},
                     {"endpoint": "a:443", "state": "SUPPORTED", "tls_version": "1.2",
                      "evidence_id": "ENUM-3", "enumeration_complete": True})
    verdict = ts.minimum(result, endpoint="a:443")
    assert verdict["version"] == "TLS1.2"
    assert verdict["basis"] == "SUPPORTED_ENUMERATION"


def test_a_negotiated_version_is_never_a_minimum():
    result = _result({"endpoint": "legacy:443", "state": "NEGOTIATED",
                      "tls_version": "1.2", "evidence_id": "NET-2"})
    verdict = ts.minimum(result, endpoint="legacy:443")
    assert verdict["basis"] == "NEGOTIATED_ONLY"
    assert verdict["claimable"] is False
    assert "not the endpoint's minimum" in verdict["statement"]


def test_an_endpoint_nobody_observed_has_no_minimum():
    verdict = ts.minimum(_result(), endpoint="ghost:443")
    assert verdict["version"] is None and verdict["claimable"] is False


# --------------------------------------------------------------------------- #
# the document


def _bom():
    return {"bomFormat": "CycloneDX", "specVersion": "1.5",
            "components": [{"type": "network-endpoint", "bom-ref": "endpoint:1",
                            "name": PAYMENTS},
                           {"type": "network-endpoint", "bom-ref": "endpoint:2",
                            "name": "other:443"}]}


def test_the_three_states_become_separate_properties():
    document = ts.attach(_bom(), _result())
    properties = [row for row in document["components"][0]["properties"]]
    names = [row["name"] for row in properties]
    assert "cryptoscan:supported_tls_version" in names
    assert "cryptoscan:configured_tls_version" in names
    assert "cryptoscan:negotiated_tls_version" in names
    assert "cryptoscan:tls_version" not in names  # no merged property to misread


def test_the_enumeration_flag_travels_with_the_endpoint():
    properties = {row["name"]: row["value"]
                  for row in ts.properties(_endpoint(_result()))}
    assert properties["cryptoscan:tls_enumeration_complete"] == "true"


def test_an_endpoint_the_model_does_not_know_is_left_alone():
    document = ts.attach(_bom(), _result())
    assert "properties" not in document["components"][1]


def test_the_summary_names_the_endpoints_only_negotiation_was_seen_on():
    result = _result(*ROWS, {"endpoint": "legacy:443", "state": "NEGOTIATED",
                             "tls_version": "1.2", "evidence_id": "NET-2"})
    summary = ts.summary(result)
    assert summary["negotiated_only"] == ["legacy:443"]
    assert "nothing may be claimed about what else they support" in summary["statement"]
