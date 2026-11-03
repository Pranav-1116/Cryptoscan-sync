"""Guide 163 tests — passive observation behind an enforced privacy contract."""

from __future__ import annotations

import pytest

from cbom import passive_observation as po

CONTRACT = dict(
    contract_id="DPC-2026-01", owner="dpo@bank.example",
    purposes=["CRYPTO_INVENTORY", "WEAK_PROTOCOL_DETECTION"],
    lawful_basis="legitimate interest: protecting our own network",
    salt_id="salt-2026q4",
    collects=["dst", "dst_port", "protocol", "tls_version", "cipher_suite", "kex_group",
              "certificate_sha256", "first_seen", "last_seen", "evidence_id",
              "client_address", "server_name", "ja3"],
)
CAPTURE = {
    "evidence_id": "CAP-1", "dst": "10.20.1.10", "dst_port": 443, "protocol": "tls",
    "tls_version": "TLSv1.2", "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "kex_group": "x25519", "certificate_sha256": "ab" * 32,
    "first_seen": "2026-11-01T00:00:00Z", "last_seen": "2026-11-01T00:10:00Z",
    "client_address": "10.30.4.51", "server_name": "payments.bank.example",
    "ja3": "ab12",
}


def _contract(**overrides):
    return po.contract(**{**CONTRACT, **overrides})


def test_a_contract_without_an_id_owner_and_purpose_is_not_enforceable():
    body = po.contract()
    assert body["enforceable"] is False
    assert len(body["problems"]) >= 4
    assert body["problems"][0].startswith("a contract needs an id")


def test_a_complete_contract_is_enforceable_and_states_its_retention():
    body = _contract()
    assert body["enforceable"] is True
    assert "90d metadata / 30d pseudonymous" in body["statement"]


def test_a_prohibited_field_cannot_be_contracted_for():
    body = _contract(collects=[*CONTRACT["collects"], "payload"])
    assert body["enforceable"] is False
    assert any("payload is prohibited" in problem for problem in body["problems"])


def test_an_unsupported_purpose_is_rejected():
    body = _contract(purposes=["MARKETING"])
    assert any("unsupported purpose" in problem for problem in body["problems"])


def test_pseudonymous_retention_may_not_outlive_metadata():
    body = _contract(retention_days={"METADATA": 30, "PSEUDONYMOUS": 90})
    assert any("must not outlive" in problem for problem in body["problems"])


def test_pseudonymous_collection_needs_a_salt_id():
    body = _contract(salt_id=None)
    assert any("salt id" in problem for problem in body["problems"])


def test_a_record_is_refused_without_an_enforceable_contract():
    with pytest.raises(ValueError, match="not enforceable"):
        po.observe(CAPTURE, privacy=po.contract(), salt="s")


def test_a_record_without_evidence_is_refused():
    with pytest.raises(ValueError, match="no evidence id|without an evidence"):
        po.observe({k: v for k, v in CAPTURE.items() if k != "evidence_id"},
                   privacy=_contract(), salt="s")


@pytest.mark.parametrize("field", ["payload", "cookie", "authorization", "token"])
def test_a_prohibited_field_is_refused_rather_than_stripped(field):
    with pytest.raises(ValueError, match="prohibited field"):
        po.observe({**CAPTURE, field: "secret"}, privacy=_contract(), salt="s")


def test_an_unclassifiable_field_is_refused():
    with pytest.raises(ValueError, match="cannot classify"):
        po.observe({**CAPTURE, "session_ticket": "x"}, privacy=_contract(), salt="s")


def test_a_field_outside_the_contract_is_refused():
    with pytest.raises(ValueError, match="outside the contract"):
        po.observe({**CAPTURE, "src": "10.30.4.51"}, privacy=_contract(), salt="s")


def test_pseudonyms_are_keyed_one_way_and_salt_specific():
    body = po.observe(CAPTURE, privacy=_contract(), salt="salt-one")
    other = po.observe(CAPTURE, privacy=_contract(), salt="salt-two")
    assert body["fields"]["client_address"].startswith("p-")
    assert body["fields"]["client_address"] != other["fields"]["client_address"]
    assert "10.30.4.51" not in str(body)
    assert body["fields"]["dst"] == "10.20.1.10"


def test_a_missing_salt_refuses_rather_than_storing_the_raw_value():
    contract = _contract()
    with pytest.raises(ValueError, match="no salt was supplied"):
        po.observe(CAPTURE, privacy=contract, salt=None)


def test_an_observation_expires_with_its_shortest_lived_field():
    body = po.observe(CAPTURE, privacy=_contract(), salt="s")
    assert body["expires_with"] == "PSEUDONYMOUS"
    assert body["expires_at"].startswith("2026-12-01")


def test_an_observation_past_retention_is_expired_and_not_evidence():
    old = {**CAPTURE, "first_seen": "2025-01-01T00:00:00Z",
           "last_seen": "2025-01-02T00:00:00Z"}
    estate = po.estate([old], privacy=_contract(), salt="s",
                       as_of="2026-11-03T00:00:00Z")
    assert estate["expired"] == ["CAP-1"]
    assert estate["live"] == 0
    assert po.to_algorithms(estate)["facts"] == []


def test_every_observation_is_observed_and_only_observed():
    body = po.observe(CAPTURE, privacy=_contract(), salt="s")
    assert body["confidence"] == "OBSERVED"
    assert body["contract_id"] == "DPC-2026-01"
    assert body["pseudonym_salt"] == "salt-2026q4"


def test_the_estate_keeps_refusals_visible():
    body = po.estate([CAPTURE, {**CAPTURE, "evidence_id": "CAP-2", "payload": "x"}],
                     privacy=_contract(), salt="s")
    assert len(body["observations"]) == 1
    assert len(body["refused"]) == 1
    assert "1 refused" in body["statement"]


def test_facts_carry_the_collection_method_and_contract():
    body = po.to_algorithms(po.estate([CAPTURE], privacy=_contract(), salt="s"))
    assert body["facts"]
    assert all(fact["collection"] == "PASSIVE" and fact["confidence"] == "OBSERVED"
               and fact["contract_id"] == "DPC-2026-01" for fact in body["facts"])
    assert {fact["role"] for fact in body["facts"]} >= {
        "BULK", "KEY_EXCHANGE", "PROTOCOL"}


def test_a_foreign_document_is_refused_by_to_algorithms():
    with pytest.raises(ValueError, match="not a"):
        po.to_algorithms({"observations": []})


def test_the_summary_states_what_a_passive_observer_cannot_prove():
    body = po.summary(po.estate([CAPTURE], privacy=_contract(), salt="s"))
    assert any("one conversation" in line for line in body["not_proven"])
    assert any("pseudonym" in line for line in body["not_proven"])
    assert body["live"] == 1
