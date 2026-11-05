"""Client-side handshake offers, end to end: probe feed → estate → protocol floor.

The gap this closes: "runtime client acceptance — what a client actually offers in a
real handshake is not evidence this build collects". These tests walk the whole chain:
a probe or sensor submits observed ClientHellos, the fail-closed intake stores them as
offers (never negotiations), the NETWORK plane folds them into the estate keyed by the
client's address rather than its ephemeral port, and the floor reports them under their
own basis — beside a list of clients the estate knows exist but has never seen offer
anything.
"""

from __future__ import annotations

import pytest

import test_network_protocol_safety as shared_api

api_fixture = pytest.fixture(name="api")(shared_api.client.__wrapped__)

OFFERS = "/api/v1/network/crypto-client-offers"
SCAN = "/api/v1/estate/evidence/scan"
FLOOR = "/api/v1/estate/evidence/twin/protocol-floor"


def _ingest(http, observations):
    response = http.post(OFFERS, json={"observations": observations, "scope_name": "probe-feed"})
    assert response.status_code == 200, response.text
    return response.json()


def _observation(**over):
    value = {
        "client_ip": "10.20.30.40",
        "client_port": 51234,
        "probe_endpoint": "10.20.30.9:8443",
        "sni": "payments.bank.example",
        "offered_versions": ["TLSv1.0", "TLSv1.2"],
        "offered_cipher_suites": ["0x002F", "TLS_AES_128_GCM_SHA256"],
        "grease_values_seen": 1,
        "versions_field": "supported_versions",
    }
    value.update(over)
    return value


def test_an_observed_clienthello_reaches_the_floor_as_an_offer_not_a_handshake(api):
    http, _session = api
    body = _ingest(http, [_observation()])
    assert body["stored"] == 1
    assert body["evidence"][0]["handshake_role"] == "CLIENT_HELLO_OFFER"
    assert body["evidence"][0]["tls_version"] is None  # nothing was negotiated

    scan = http.post(SCAN, json={"force": True})
    assert scan.status_code == 200, scan.text

    floor = http.get(FLOOR, params={"floor": "TLSv1.2"})
    assert floor.status_code == 200, floor.text
    document = floor.json()

    assert document["status"] == "BELOW_FLOOR_OFFERED"
    offers = document["client_offers"]
    assert offers["counts"]["clients_offering_below_floor"] == 1
    entry = offers["clients_offering_below_floor"][0]
    assert entry["offers_below_floor"] == ["TLSv1.0"]
    assert entry["sni"] == "payments.bank.example"
    # the offer never became a negotiated record
    assert all(row.get("negotiated") != "TLSv1.0" for row in document["below_floor"])
    assert "an offer is what a client put on the wire" in offers["meaning"]


def test_the_estate_keys_a_client_by_its_address_not_its_ephemeral_port(api):
    http, _session = api
    _ingest(http, [
        _observation(client_port=51234),
        _observation(client_port=62000, offered_versions=["TLSv1.3"]),
    ])
    scan = http.post(SCAN, json={"force": True})
    assert scan.status_code == 200, scan.text

    floor = http.get(FLOOR, params={"floor": "TLSv1.2"})
    document = floor.json()
    offers = document["client_offers"]

    # two connections, one client: one asset with two offer records, never two assets
    assert offers["counts"]["offer_records"] == 2
    assert offers["counts"]["clients_with_offer_evidence"] == 1
    assert document["counts"]["clients_offering_below_floor"] == 1
    assert document["counts"]["client_offer_records"] == 2


def test_a_value_the_parser_cannot_rank_stays_unrecognised_through_the_api(api):
    http, _session = api
    _ingest(http, [_observation(offered_versions=["0x1234"])])
    http.post(SCAN, json={"force": True})

    floor = http.get(FLOOR, params={"floor": "TLSv1.2"})
    document = floor.json()

    assert document["client_offers"]["counts"]["unrecognised"] == 1
    assert document["client_offers"]["unrecognised"][0]["unrecognised"] == ["0x1234"]
    # an unrankable offer is not "at or above the floor" — not in the offer axis, and
    # not in the status either
    assert document["client_offers"]["clients_offering_at_or_above_floor"] == []
    assert document["status"] == "UNRANKED_EVIDENCE_ONLY"
    assert document["client_offers"]["counts"]["clients_offering_below_floor"] == 0


def test_the_intake_refuses_content_and_refuses_an_offer_with_no_offered_values(api):
    http, _session = api

    refused = http.post(OFFERS, json={"observations": [_observation(payload="captured bytes")]})
    assert refused.status_code == 422
    assert "client_offer_observation_rejected" in refused.text

    empty = http.post(OFFERS, json={"observations": [_observation(offered_versions=[])]})
    assert empty.status_code == 422

    no_client = http.post(OFFERS, json={"observations": [{"offered_versions": ["TLSv1.0"]}]})
    assert no_client.status_code == 422
    assert "client_ip is required" in no_client.text


def test_the_ingest_response_states_what_an_offer_is_not(api):
    http, _session = api
    body = _ingest(http, [_observation()])

    assert "not a negotiation and not a use" in body["note"]
    assert body["active_packets"] == 0
    record = body["evidence"][0]
    assert "not a negotiation" in record["limitations"][0]
    assert "NOT_OBSERVED, never assumed compliant" in record["limitations"][1]
