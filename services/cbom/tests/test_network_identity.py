"""Review item 20: a network asset has an identity that outlives its address."""

from __future__ import annotations

import pytest

from cbom import network_identity as ni

LB = {
    "asset_id": "NET-001928", "type": "LOAD_BALANCER", "hostname": "ext-lb-prod-01",
    "ips": ["10.20.1.10", "10.20.1.11"], "environment": "PRODUCTION", "zone": "DMZ",
    "location": "DC1", "certificate": {"fingerprint_sha256": "CERT-9281"},
    "sni": "payments.bank.example", "collector_source": "authorized-scanner",
    "evidence_id": "NET-1", "observed_at": "2026-11-01T00:00:00Z",
}
WAF = {
    "hostname": "ext-waf-prod-01", "type": "WAF", "ips": ["10.20.1.20"],
    "environment": "PRODUCTION", "zone": "DMZ", "collector_source": "cmdb-export",
    "evidence_id": "CMDB-1", "observed_at": "2026-11-01T00:00:00Z",
}


def test_the_reviews_own_example_is_one_asset():
    record = ni.identity(LB)
    assert record["asset_id"] == "NET-001928"
    assert record["asset_id_source"] == "EXPLICIT"
    assert record["type"] == "LOAD_BALANCER"
    assert record["ips"] == ["10.20.1.10", "10.20.1.11"]
    assert record["certificates"] == ["CERT-9281"]
    assert record["environment"] == "PRODUCTION" and record["zone"] == "DMZ"
    assert record["private_material"] == "NOT_STORED"


def test_an_ip_and_a_port_are_refused_rather_than_named():
    for row in ({"ip": "10.20.1.10", "port": 443}, {"endpoint": "10.20.1.10:443"}):
        with pytest.raises(ValueError, match="IP:port is not an identity"):
            ni.identity(row)
    merged = ni.merge([{"ip": "10.20.1.10", "port": 443}])
    assert merged["assets"] == []
    assert "IP:port is not an identity" in merged["refused"][0]["reason"]


def test_the_same_host_on_a_new_address_is_the_same_asset():
    moved = {**LB, "ips": ["10.20.1.12"], "evidence_id": "NET-9",
             "observed_at": "2026-11-02T00:00:00Z"}
    before, after = ni.merge([LB]), ni.merge([moved])
    assert before["assets"][0]["asset_id"] == after["assets"][0]["asset_id"]
    body = ni.churn(before, after)
    assert body["counts"] == {"IP_ADDED": 1, "IP_REMOVED": 2}
    assert body["identity_stable"] is True
    assert "moved under the same asset id" in body["statement"]


def test_a_derived_identity_does_not_depend_on_an_address():
    first = ni.identity({**WAF, "ips": ["10.20.1.20"]})
    second = ni.identity({**WAF, "ips": ["10.20.9.99"]})
    assert first["asset_id"] == second["asset_id"]
    assert first["asset_id"].startswith("NET-") and len(first["asset_id"]) == 14
    assert first["asset_id_source"] == "DERIVED"


def test_a_derived_identity_does_depend_on_where_the_device_is():
    prod = ni.identity(WAF)
    test = ni.identity({**WAF, "environment": "TEST"})
    other_zone = ni.identity({**WAF, "zone": "CORE", "location": None})
    assert prod["asset_id"] != test["asset_id"]
    assert prod["asset_id"] != other_zone["asset_id"]


def test_two_collectors_seeing_one_device_are_one_asset():
    from_network = ni.identity({**WAF, "collector_source": "authorized-scanner",
                                "evidence_id": "NET-2"})
    from_cmdb = ni.identity({**WAF, "collector_source": "cmdb-export",
                             "evidence_id": "CMDB-1"})
    assert from_network["asset_id"] == from_cmdb["asset_id"]
    merged = ni.merge([{**WAF, "collector_source": "authorized-scanner",
                        "evidence_id": "NET-2"},
                       {**WAF, "collector_source": "cmdb-export",
                        "evidence_id": "CMDB-1"}])
    record = merged["assets"][0]
    assert record["collector_sources"] == ["authorized-scanner", "cmdb-export"]
    assert record["evidence_ids"] == ["CMDB-1", "NET-2"]
    assert record["observation_count"] == 2


def test_address_history_keeps_first_and_last_seen_per_address():
    merged = ni.merge([
        {**LB, "ips": ["10.20.1.10"], "evidence_id": "NET-1",
         "observed_at": "2026-11-01T00:00:00Z"},
        {**LB, "ips": ["10.20.1.10", "10.20.1.11"], "evidence_id": "NET-2",
         "observed_at": "2026-11-03T00:00:00Z"},
    ])
    history = {item["ip"]: item for item in merged["assets"][0]["ip_history"]}
    assert history["10.20.1.10"] == {"ip": "10.20.1.10",
                                     "first_seen": "2026-11-01T00:00:00Z",
                                     "last_seen": "2026-11-03T00:00:00Z",
                                     "collector_sources": ["authorized-scanner"]}
    assert history["10.20.1.11"]["first_seen"] == "2026-11-03T00:00:00Z"


def test_an_observation_with_no_timestamp_cannot_date_an_address():
    merged = ni.merge([{**WAF, "observed_at": None}])
    assert merged["assets"][0]["ip_history"][0]["first_seen"] is None
    assert merged["assets"][0]["multiple_addresses"] is False


def test_two_device_types_under_one_identity_are_a_conflict_not_a_choice():
    merged = ni.merge([{**LB, "type": "LOAD_BALANCER"},
                       {**LB, "type": "WAF", "evidence_id": "NET-5"}])
    record = merged["assets"][0]
    assert {"field": "type", "values": ["LOAD_BALANCER", "WAF"]} in record["conflicts"]
    assert record["type"] == "LOAD_BALANCER"


def test_an_unknown_type_is_recorded_as_unknown_and_listed():
    merged = ni.merge([{**WAF, "type": None}])
    assert merged["assets"][0]["type"] == "UNKNOWN"
    assert merged["untyped"] == [merged["assets"][0]["asset_id"]]


def test_a_type_outside_the_vocabulary_is_refused():
    with pytest.raises(ValueError, match="not an asset type this model records"):
        ni.identity({**WAF, "type": "MAINFRAME_THING"})


def test_a_certificate_rotation_keeps_the_asset_and_reports_the_change():
    before = ni.merge([LB])
    after = ni.merge([{**LB, "certificate": {"fingerprint_sha256": "CERT-9999"},
                       "evidence_id": "NET-9", "observed_at": "2026-11-02T00:00:00Z"}])
    body = ni.churn(before, after)
    assert body["counts"] == {"CERTIFICATE_CHANGED": 2}
    assert body["identity_stable"] is True


def test_a_disappearance_is_a_question_for_the_owner_not_a_deletion():
    before = ni.merge([LB, WAF])
    after = ni.merge([LB])
    body = ni.churn(before, after)
    retired = [change for change in body["changes"]
               if change["kind"] == "ASSET_RETIRED"]
    assert len(retired) == 1
    assert "retired and not answering are indistinguishable" in retired[0]["detail"]
    assert body["identity_stable"] is False


def test_a_churn_report_refuses_two_things_that_are_not_inventories():
    good = ni.merge([LB])
    with pytest.raises(ValueError, match="not a"):
        ni.churn({"assets": []}, good)
    with pytest.raises(ValueError, match="not a"):
        ni.churn(good, {"schema": "something-else", "assets": []})


def test_an_interface_is_not_an_application_without_a_mapping():
    body = ni.link(ni.merge([LB])["assets"])
    row = body["links"][0]
    assert row["applications"] == [] and row["inference"] == "NOT_PROVEN"
    assert "interface fact" in row["statement"]
    assert body["proven"] == 0 and body["unproven"] == 1


def test_a_mapping_without_an_evidence_id_is_a_claim_not_evidence():
    assets = ni.merge([LB])["assets"]
    body = ni.link(assets, {"NET-001928": {"applications": ["Payments API"]}})
    assert body["links"][0]["inference"] == "NOT_PROVEN"
    assert "no evidence id" in body["links"][0]["reason"]
    proven = ni.link(assets, {"NET-001928": {"applications": ["Payments API"],
                                             "evidence_id": "CMDB-7",
                                             "source": "CMDB"}})
    assert proven["links"][0]["inference"] == "PROVEN"
    assert proven["links"][0]["source"] == "CMDB"
    assert "declared to serve Payments API (CMDB-7)" in proven["links"][0]["statement"]


def test_a_mapping_keyed_by_hostname_still_works():
    body = ni.link(ni.merge([LB])["assets"],
                   {"ext-lb-prod-01": {"applications": ["Payments API"],
                                       "evidence_id": "CMDB-7"}})
    assert body["links"][0]["inference"] == "PROVEN"


def test_the_summary_counts_addresses_under_identities_not_assets():
    inventory = ni.merge([LB, WAF])
    body = ni.summary(inventory)
    assert body["assets"] == 2
    assert body["addresses"] == 3
    assert body["multi_address"] == ["NET-001928"]
    assert body["refused"] == 0
    assert any("new asset" in line for line in body["not_proven"])


def test_the_identity_of_one_observation_is_stable_under_reordering():
    rows = [LB, WAF, {**WAF, "collector_source": "second-collector",
                      "evidence_id": "NET-3"}]
    forward = ni.merge(rows)
    backward = ni.merge(list(reversed(rows)))
    assert [asset["asset_id"] for asset in forward["assets"]] == [
        asset["asset_id"] for asset in backward["assets"]]
    assert forward["statement"] == backward["statement"]


def test_a_hop_asset_is_attached_to_the_device_that_terminated_it():
    from cbom import network_assets as na

    hops = [{"from": "Internet", "to": "External LB", "endpoint": "payments.bank.example:443",
             "observed_on": "External LB", "tls_version": "1.3",
             "cipher_suite": "TLS_AES_256_GCM_SHA384", "evidence_id": "NET-1"}]
    observed = na.assets(hops)
    assert observed["assets"], "guide 148 must produce the hop asset first"
    records = ni.merge([{**LB, "hostname": "external lb"}])["assets"]
    body = ni.resolve(observed["assets"], records)
    assert body["resolved"] == len(observed["assets"])
    row = body["rows"][0]
    assert row["asset_id"] == "NET-001928"
    assert row["interface_role"] == "LOAD_BALANCER"
    assert "attached to an asset identity" in body["statement"]


def test_an_interface_with_no_record_stays_unresolved():
    body = ni.resolve([{"endpoint": "payments.bank.example:443", "algorithm": "AES-256-GCM",
                        "observed_on": "Mystery Box"}], ni.merge([LB])["assets"])
    assert body["rows"][0]["asset_id"] is None
    assert body["rows"][0]["resolution"] == "UNRESOLVED"
    assert "no inventory record carries Mystery Box" in body["rows"][0]["reason"]
