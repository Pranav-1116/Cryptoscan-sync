"""Guide 181 — the security control integration layer.

These tests are the specification's acceptance criteria, expressed where they cannot drift: a
collector cannot grow a write, a prohibited value cannot survive a cycle, a claim cannot
arrive without evidence, and the three fact classes cannot merge.
"""

from __future__ import annotations

import inspect
import json

import pytest

from cbom import security_controls as sc
from cbom import techbom


# --------------------------------------------------------------------------- #
# fixtures: one small estate, recorded once
# --------------------------------------------------------------------------- #

def firewall_feed() -> dict:
    return {
        "system": "FW-EDGE-01",
        "assets": [
            {"kind": "FIREWALL", "name": "FW-EDGE-01", "version": "7.4.3",
             "vendor": "Fortinet"},
            {"kind": "NETWORK_SEGMENT", "name": "PAYMENTS-SEG"},
            {"kind": "NETWORK_SEGMENT", "name": "INTERNET"},
        ],
        "sections": {
            "firewall_policy": [
                {"srcintf": "INTERNET", "dstintf": "PAYMENTS-SEG", "service": "HTTPS",
                 "action": "accept", "password": "hunter2", "api_secret": "sk-live-abc123"},
                {"srcintf": "PAYMENTS-SEG", "dstintf": "INTERNET", "service": "HTTPS",
                 "action": "deny"},
            ],
            "system_zone": [{"name": "PAYMENTS-SEG", "interface": ["port3"]}],
            "vpn_ipsec_phase1": [{"name": "TUN-HQ", "psk": "shared-secret-value"}],
        },
        "relationships": [
            {"from": "FW-EDGE-01", "relation": "PROTECTS", "to": "PAYMENTS-SEG",
             "basis": "config-parse", "evidence": "fw-rule-1",
             "facts": {"port": 443, "protocol": "tcp", "rule": "FW-001"}},
            {"from": "FW-EDGE-01", "relation": "PRESENTS", "to": "PAYMENTS-SEG",
             "basis": "config-parse", "evidence": "fw-rule-2"},
            {"from": "FW-EDGE-01", "relation": "ALLOWS", "to": "PAYMENTS-SEG",
             "basis": "config-parse", "evidence": "fw-rule-3"},
            {"from": "FW-EDGE-01", "relation": "PROTECTS", "to": "NOBODY-DECLARED-THIS",
             "basis": "config-parse", "evidence": "fw-rule-4"},
            {"from": "FW-EDGE-01", "relation": "PROTECTS", "to": "INTERNET",
             "basis": "co-occurrence"},
            {"from": "FW-EDGE-01", "relation": "INSPECTS", "to": "PAYMENTS-SEG",
             "basis": "config-parse"},
        ],
        "health": {"reachable": True, "read_only": True},
    }


def ids_feed() -> dict:
    return {
        "system": "IDS-SENSOR-01",
        "assets": [{"kind": "IDS", "name": "IDS-SENSOR-01", "version": "6.0.9"}],
        "sections": {
            "eve": [{"signature_id": "2001219", "rev": "19", "src_ip": "10.20.3.4",
                     "dest_ip": "10.30.1.10", "proto": "TCP", "dest_port": 443,
                     "tls_version": "TLSv1.2", "sni": "payments.internal",
                     "payload": "POST /payments HTTP/1.1\r\nAuthorization: Bearer abc12345"}],
            "rules": [{"sid": "2001219", "rev": "19", "classification": "attempted-recon",
                       "enabled": True}],
        },
        "events": [
            {"kind": "ALERT", "signature": "2001219", "src": "10.20.3.4",
             "dst": "10.30.1.10", "protocol": "tcp", "port": 443, "tls_version": "TLSv1.2",
             "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
             "sni": "payments.internal", "timestamp": "2026-11-03T09:14:00Z",
             "payload": "POST /payments HTTP/1.1\r\nCookie: session=abc",
             "authorization": "Bearer abc12345"},
            {"kind": "TELEMETRY", "signature": "n/a"},
        ],
        "health": {"reachable": True},
    }


def rate_limit_feed() -> dict:
    return {
        "system": "GW-API-01",
        "assets": [{"kind": "API_GATEWAY", "name": "GW-API-01"},
                   {"kind": "RATE_LIMIT", "name": "LIMIT-PAYMENTS"},
                   {"kind": "APPLICATION", "name": "PAYMENTS-API"}],
        "sections": {
            "quotas": [
                {"name": "LIMIT-PAYMENTS", "quota": 100, "window": 60, "enabled": True,
                 "targets": ["PAYMENTS-API"]},
                {"name": "LIMIT-ORPHAN", "quota": 50, "window": 60, "enabled": True},
            ],
            "apis": [{"quota_id": "LIMIT-PAYMENTS", "api_id": "PAYMENTS-API"}],
            "events": [{"quota_id": "LIMIT-PAYMENTS", "api_id": "PAYMENTS-API",
                        "count": 1000, "at": "2026-11-03T09:00:00Z"}],
        },
        "traffic": [
            {"api": "PAYMENTS-API", "requests": 900, "window_seconds": 60,
             "evidence_id": "OBS-NET-0001"},
            {"api": "REPORTS-API", "requests": 40, "window_seconds": 60,
             "evidence_id": "OBS-NET-0002"},
            {"api": "NO-EVIDENCE-API", "requests": 10, "window_seconds": 60},
        ],
        "health": {"reachable": True},
    }


def events_feed() -> dict:
    return {
        "system": "SIEM-01",
        "assets": [{"kind": "SECURITY_APPLIANCE", "name": "SIEM-01"}],
        "events": [{"kind": "ALERT", "signature": "corr-17", "src": "10.20.3.4",
                    "timestamp": "2026-11-03T09:14:00Z", "incident_id": "INC-77"}],
        "sections": {"correlations": [{"rule_id": "corr-17", "search_id": "sid-1",
                                       "incident_id": "INC-77",
                                       "detected_at": "2026-11-03T09:14:10Z"}]},
        "health": {"reachable": True},
    }


def all_collectors() -> list:
    return [
        sc.collector("FIREWALL", "fortigate", firewall_feed()),
        sc.collector("IDS", "suricata", ids_feed()),
        sc.collector("RATE_LIMIT", "gateway", rate_limit_feed()),
        sc.collector("SIEM", "splunk", events_feed()),
    ]


# --------------------------------------------------------------------------- #
# SC-01 the contract is six verbs and none of them writes
# --------------------------------------------------------------------------- #

#: method names a collector may never gain. "signatures" and "blocks" are reads and are
#: deliberately not matched by these stems.
WRITE_WORDS = ("write", "push", "apply", "reload", "restart", "create", "update",
               "delete", "rotate", "revoke", "generate", "throttle", "tune",
               "disable", "encrypt", "decrypt")


def test_sc01_the_contract_has_exactly_the_six_verbs():
    abstract = set(sc.SecurityControlCollector.__abstractmethods__)
    assert abstract == {"discover_assets", "collect_configuration", "collect_crypto_metadata",
                        "collect_relationships", "collect_security_events", "health"}


def test_sc01_no_collector_exposes_a_mutating_method():
    offenders = []
    for cls in (sc.SecurityControlCollector, sc.DeviceCollector, *[
            getattr(__import__(f"cbom.security_controls.{name}.base", fromlist=["base"]), attr)
            for name, attr in (("firewall", "FirewallCollector"),
                               ("ids", "IdsCollector"),
                               ("ips", "IpsCollector"),
                               ("waf", "WafCollector"),
                               ("load_balancer", "LoadBalancerCollector"),
                               ("api_gateway", "ApiGatewayCollector"),
                               ("rate_limit", "RateLimitCollector"),
                               ("vpn", "VpnCollector"),
                               ("siem", "SiemCollector"))]):
        for method, _ in inspect.getmembers(cls, predicate=inspect.isfunction):
            if method.startswith("_"):
                continue
            if any(word in method for word in WRITE_WORDS):
                offenders.append(f"{cls.__name__}.{method}")
    assert offenders == []


def test_sc01_the_collector_is_read_only_by_declaration_and_by_construction():
    collector = sc.collector("FIREWALL", "fortigate", firewall_feed())
    assert collector.read_only is True
    capabilities = collector.capabilities()
    assert capabilities["write_operations"] == []
    assert set(capabilities["read_operations"]) <= sc.READ_OPERATIONS


# --------------------------------------------------------------------------- #
# SC-02 a vendor cannot declare a write
# --------------------------------------------------------------------------- #

def test_sc02_an_adapter_that_declares_a_write_is_refused_at_registration():
    with pytest.raises(sc.ControlRefused) as refused:
        sc.AdapterSpec(key="bad", control="FIREWALL", vendor="X", product="Y",
                       operations=("API_GET", "PUSH_POLICY"))
    assert refused.value.code == "NOT_READ_ONLY"


@pytest.mark.parametrize("verb", ["POST", "PUT", "DELETE", "COMMIT", "BLOCK", "SET"])
def test_sc02_every_mutating_verb_is_caught(verb):
    with pytest.raises(sc.ControlRefused):
        sc.AdapterSpec(key="bad", control="WAF", vendor="X", product="Y",
                       operations=(verb,))


def test_sc02_an_unclassifiable_operation_is_refused_rather_than_assumed_harmless():
    with pytest.raises(sc.ControlRefused) as refused:
        sc.AdapterSpec(key="bad", control="VPN", vendor="X", product="Y",
                       operations=("MASSAGE_CONFIG_MAGICALLY",))
    assert refused.value.code == "NOT_READ_ONLY"


def test_sc02_a_mutating_endpoint_cannot_be_documented():
    with pytest.raises(sc.ControlRefused) as refused:
        sc.AdapterSpec(key="bad", control="FIREWALL", vendor="X", product="Y",
                       endpoints=("POST /api/v2/cmdb/firewall/policy",))
    assert refused.value.code == "NOT_READ_ONLY"


def test_sc02_an_unknown_control_type_is_refused():
    with pytest.raises(sc.ControlRefused) as refused:
        sc.AdapterSpec(key="bad", control="TEAPOT", vendor="X", product="Y")
    assert refused.value.code == "UNKNOWN_CONTROL"


def test_sc02_the_whole_registry_is_read_only():
    audit = sc.read_only_audit()
    assert audit["read_only"] is True
    assert audit["adapters_with_writes"] == []
    assert audit["adapters"] >= 25
    assert set(audit["controls"]) == {"FIREWALL", "IDS", "IPS", "WAF", "LOAD_BALANCER",
                                      "API_GATEWAY", "RATE_LIMIT", "VPN", "SIEM"}


def test_sc02_every_declared_operation_is_on_the_read_allow_list():
    for key, capabilities in sc.adapters().items():
        assert set(capabilities["read_operations"]) <= sc.READ_OPERATIONS, key


# --------------------------------------------------------------------------- #
# SC-03 prohibited values do not survive
# --------------------------------------------------------------------------- #

SECRETS = ("hunter2", "sk-live-abc123", "shared-secret-value", "Bearer abc12345",
           "session=abc")


def snapshot_json(collector) -> str:
    return json.dumps(collector.snapshot(), default=str, sort_keys=True)


def test_sc03_no_prohibited_value_survives_a_collection_cycle():
    for collector in all_collectors():
        dumped = snapshot_json(collector)
        for secret in SECRETS:
            assert secret not in dumped, f"{secret!r} survived {collector.spec.key}"
        assert "PRIVATE KEY" not in dumped


def test_sc03_the_redaction_is_recorded_rather_than_hidden():
    collector = sc.collector("FIREWALL", "fortigate", firewall_feed())
    collector.collect_configuration()
    reasons = {item["reason"] for item in collector.redactions}
    fields = {item["field"] for item in collector.redactions}
    assert "PROHIBITED_FIELD" in reasons
    assert {"password", "api_secret", "psk"} <= fields
    assert all(item["reason"] != "PROHIBITED_FIELD" or item["path"] for item in
               collector.redactions)


def test_sc03_a_private_key_is_caught_by_shape_even_under_an_innocent_name():
    clean, redactions = sc.scrub({"notes": "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."})
    assert clean["notes"] == sc.REDACTED
    assert redactions[0]["reason"] == "PEM_PRIVATE_KEY"


def test_sc03_a_pem_in_a_section_row_does_not_reach_the_configuration():
    feed = firewall_feed()
    feed["sections"]["firewall_policy"][0]["comment"] = (
        "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----")
    collector = sc.collector("FIREWALL", "fortigate", feed)
    rows = collector.collect_configuration()["sections"]["rules"]
    assert "BEGIN PRIVATE KEY" not in json.dumps(rows)


def test_sc03_card_numbers_and_authorization_headers_are_shapes_not_names():
    clean, redactions = sc.scrub({
        "summary": "4111 1111 1111 1111",
        "header_text": "Authorization: Basic dXNlcjpwYXNz",
        "trace": "request failed",
    })
    assert clean["summary"] == sc.REDACTED
    assert clean["header_text"] == sc.REDACTED
    assert clean["trace"] == "request failed"
    assert {item["reason"] for item in redactions} == {"CARD_NUMBER",
                                                      "AUTHORIZATION_HEADER"}


def test_sc03_a_payload_shaped_event_field_is_dropped_before_normalization():
    collector = sc.collector("IDS", "suricata", ids_feed())
    event = collector.collect_security_events()[0]
    assert "payload" not in event["metadata"]
    assert "Bearer abc12345" not in json.dumps(event, default=str)


def test_sc03_the_prohibition_list_is_declared_on_every_adapter():
    for capabilities in sc.adapters().values():
        assert "private_keys" in capabilities["never_collects"]
        assert "hsm_key_material" in capabilities["never_collects"]
        assert "http_bodies" in capabilities["never_collects"]


# --------------------------------------------------------------------------- #
# SC-04 configured, observed and runtime stay apart
# --------------------------------------------------------------------------- #

def test_sc04_a_configuration_row_is_configured_and_an_event_is_observed():
    collector = sc.collector("IDS", "suricata", ids_feed())
    configuration = collector.collect_configuration()["sections"]["signatures"]
    events = collector.collect_security_events()
    assert {row["fact"] for row in configuration} == {sc.CONFIGURED}
    assert {row["fact"] for row in events} == {sc.OBSERVED}


def test_sc04_a_rate_limit_breach_carries_both_evidence_classes_and_neither_verdict():
    collector = sc.collector("RATE_LIMIT", "gateway", rate_limit_feed())
    audit = sc.audit_rate_limits(collector)
    over = [row for row in audit["findings"] if row["state"] == "OVER_LIMIT"]
    assert over, audit["findings"]
    assert over[0]["facts"] == [sc.CONFIGURED, sc.OBSERVED]
    assert len(over[0]["evidence_ids"]) == 2
    assert over[0]["expected"]["limit"] == 100
    assert over[0]["observed"]["requests"] == 900


def test_sc04_separate_facts_keeps_three_buckets_and_never_merges():
    separated = sc.separate_facts([
        {"fact": sc.CONFIGURED, "value": "limit=100"},
        {"fact": sc.OBSERVED, "value": "requests=900"},
        {"fact": sc.RUNTIME_OBSERVED, "value": "negotiated TLS1.2"},
    ])
    assert separated["separated"] is True
    assert [len(separated[name]) for name in (sc.CONFIGURED, sc.OBSERVED,
                                              sc.RUNTIME_OBSERVED)] == [1, 1, 1]


def test_sc04_a_record_with_no_fact_class_is_a_conflict_not_a_guess():
    separated = sc.separate_facts([{"value": "unclassified"}])
    assert separated["separated"] is False
    assert separated["conflict"]


def test_sc04_the_basis_decides_the_class_and_an_unknown_basis_is_refused():
    assert sc.fact_class("config-parse") == sc.CONFIGURED
    assert sc.fact_class("passive-capture") == "NETWORK_OBSERVED"
    assert sc.fact_class("runtime-probe") == sc.OBSERVED
    with pytest.raises(sc.ControlRefused):
        sc.fact_class("looks-about-right")


# --------------------------------------------------------------------------- #
# SC-05 every relationship carries its evidence
# --------------------------------------------------------------------------- #

def test_sc05_every_collected_row_carries_an_evidence_id():
    for collector in all_collectors():
        snapshot = collector.snapshot()
        for section in ("assets", "crypto", "events"):
            for row in snapshot[section]:
                assert row["evidence_id"].startswith("EVID-"), (collector.spec.key, section)
        for claims in snapshot["relationships"]:
            assert claims["evidence_ids"]


def test_sc05_evidence_ids_are_deterministic_across_two_reads():
    first = sc.collector("FIREWALL", "fortigate", firewall_feed()).snapshot()
    second = sc.collector("FIREWALL", "fortigate", firewall_feed()).snapshot()
    assert [row["evidence_id"] for row in first["assets"]] == \
           [row["evidence_id"] for row in second["assets"]]
    assert [row["evidence_ids"] for row in first["relationships"]] == \
           [row["evidence_ids"] for row in second["relationships"]]


def test_sc05_a_relationship_without_evidence_is_refused_by_name():
    collector = sc.collector("FIREWALL", "fortigate", firewall_feed())
    collector.collect_relationships()
    codes = {row["code"] for row in collector.refusals}
    assert "RELATIONSHIP_WITHOUT_EVIDENCE" in codes


def test_sc05_a_vendor_cannot_name_a_relation_of_its_own():
    collector = sc.collector("FIREWALL", "fortigate", firewall_feed())
    collector.collect_relationships()
    refusal = next(row for row in collector.refusals if row["code"] == "UNKNOWN_RELATION")
    assert refusal["subject"] == "FW-EDGE-01 ALLOWS PAYMENTS-SEG"


def test_sc05_a_basis_that_is_not_evidence_cannot_be_cited():
    collector = sc.collector("FIREWALL", "fortigate", firewall_feed())
    claims = collector.collect_relationships()
    assert all(claim["basis"] != "co-occurrence" for claim in claims)
    assert any(row["code"] == "UNKNOWN_BASIS" for row in collector.refusals)


def test_sc05_an_edge_to_an_undeclared_asset_is_named_not_invented():
    collector = sc.collector("FIREWALL", "fortigate", firewall_feed())
    collector.snapshot()
    refusal = next(row for row in collector.refusals
                   if row["code"] == "EDGE_TO_UNDECLARED_ASSET")
    assert "NOBODY-DECLARED-THIS" in refusal["subject"]


# --------------------------------------------------------------------------- #
# SC-06 the projection is typed, and its refusals are data
# --------------------------------------------------------------------------- #

def test_sc06_the_projection_builds_a_techbom_with_no_graph_refusals():
    projection = sc.project(all_collectors())
    assert projection["techbom"]["refusals"] == []
    assert projection["summary"]["assets"] >= 6
    assert set(projection["summary"]["asset_kinds"]) <= set(techbom.ASSET_TYPES)


def test_sc06_an_illegal_relation_is_refused_with_the_reason():
    projection = sc.project([sc.collector("FIREWALL", "fortigate", firewall_feed())])
    codes = {row["code"] for row in projection["refusals"]}
    assert "NO_LEGAL_RELATION" in codes
    refusal = next(row for row in projection["refusals"]
                   if row["code"] == "NO_LEGAL_RELATION")
    assert "PRESENTS starts at" in refusal["reason"]


def test_sc06_an_edge_to_a_node_nobody_declared_is_refused_not_created():
    projection = sc.project([sc.collector("FIREWALL", "fortigate", firewall_feed())])
    subjects = {row["subject"] for row in projection["refusals"]}
    assert "NOBODY-DECLARED-THIS" in subjects
    assert all("NOBODY-DECLARED-THIS" not in asset["name"]
               for asset in projection["assets"])


def test_sc06_assets_are_canonical_across_collectors():
    projection = sc.project(all_collectors())
    keys = [(row["kind"], row["name"]) for row in projection["assets"]]
    assert len(keys) == len(set(keys))


def test_sc06_the_accepted_claim_keeps_its_facts():
    projection = sc.project([sc.collector("FIREWALL", "fortigate", firewall_feed())])
    edge = next(row for row in projection["techbom"]["claims"]
                if row["relation"] == "PROTECTS")
    assert edge["facts"]["port"] == 443
    assert edge["evidence_ids"] == ["fw-rule-1"]
    assert edge["from_id"].startswith("TECH-FW-")
    assert edge["to_id"].startswith("TECH-SEG-")


def test_sc06_a_certificate_in_crypto_metadata_becomes_a_node_and_a_claim():
    feed = {
        "system": "LB-01",
        "assets": [{"kind": "LOAD_BALANCER", "name": "LB-01"}],
        "crypto": [{"asset": "LB-01", "tls_version": "TLSv1.2",
                    "certificate": {"subject": "CN=payments.internal",
                                    "issuer": "CN=Bank Issuing CA",
                                    "public_key_algorithm": "RSA",
                                    "public_key_size": 2048,
                                    "private_key": "-----BEGIN PRIVATE KEY-----"}}],
        "health": {"reachable": True},
    }
    projection = sc.project([sc.collector("LOAD_BALANCER", "f5", feed)])
    kinds = {row["name"]: row["kind"] for row in projection["assets"]}
    assert kinds["CN=payments.internal"] == "CERTIFICATE"
    relations = [row["relation"] for row in projection["techbom"]["claims"]]
    assert "USES_CERTIFICATE" in relations
    assert "PRIVATE KEY" not in json.dumps(projection, default=str)


# --------------------------------------------------------------------------- #
# SC-07 the rate-limit audit distinguishes its three states
# --------------------------------------------------------------------------- #

def test_sc07_the_three_states_are_distinguishable():
    audit = sc.audit_rate_limits(sc.collector("RATE_LIMIT", "gateway", rate_limit_feed()))
    states = {row["state"] for row in audit["findings"]}
    assert {"NOT_CONFIGURED", "OVER_LIMIT", "POLICY_NOT_ATTACHED"} <= states


def test_sc07_not_configured_names_the_api_and_carries_only_the_observation():
    audit = sc.audit_rate_limits(sc.collector("RATE_LIMIT", "gateway", rate_limit_feed()))
    finding = next(row for row in audit["findings"] if row["state"] == "NOT_CONFIGURED")
    assert finding["api"] == "REPORTS-API"
    assert finding["policy"] is None
    assert finding["facts"] == [sc.OBSERVED]
    assert "not a reading we could not take" in finding["reason"]


def test_sc07_policy_not_attached_finds_the_orphan():
    audit = sc.audit_rate_limits(sc.collector("RATE_LIMIT", "gateway", rate_limit_feed()))
    finding = next(row for row in audit["findings"]
                   if row["state"] == "POLICY_NOT_ATTACHED")
    assert finding["policy"] == "LIMIT-ORPHAN"
    assert finding["observed"] is None
    assert finding["facts"] == [sc.CONFIGURED]


def test_sc07_the_expected_number_is_the_configured_limit_in_the_observed_window():
    audit = sc.audit_rate_limits(sc.collector("RATE_LIMIT", "gateway", rate_limit_feed()))
    finding = next(row for row in audit["findings"] if row["state"] == "OVER_LIMIT")
    assert finding["expected"]["requests"] == 100.0  # 100 per 60s, observed over 60s


def test_sc07_an_observation_without_evidence_is_refused_not_counted():
    audit = sc.audit_rate_limits(sc.collector("RATE_LIMIT", "gateway", rate_limit_feed()))
    refusal = next(row for row in audit["refusals"]
                   if row["code"] == "OBSERVATION_WITHOUT_EVIDENCE")
    assert refusal["subject"] == "NO-EVIDENCE-API"
    assert "NO-EVIDENCE-API" not in audit["apis_with_traffic"]


def test_sc07_a_policy_under_its_limit_is_reported_as_within_limit_not_as_healthy():
    collector = sc.collector("RATE_LIMIT", "gateway", rate_limit_feed())
    audit = sc.audit_rate_limits(collector, traffic=[
        {"api": "PAYMENTS-API", "requests": 10, "window_seconds": 60,
         "evidence_id": "OBS-NET-0003"}])
    assert [row["state"] for row in audit["findings"] if row["api"]] == ["WITHIN_LIMIT"]


def test_sc07_the_audit_refuses_a_collector_that_is_not_a_limiter():
    with pytest.raises(sc.ControlRefused) as refused:
        sc.audit_rate_limits(sc.collector("FIREWALL", "fortigate", firewall_feed()))
    assert refused.value.code == "NOT_A_RATE_LIMITER"


# --------------------------------------------------------------------------- #
# SC-08 IDS events reach the crypto they touch
# --------------------------------------------------------------------------- #

def correlation_inputs() -> dict:
    return {
        "hosts": [{"ip": "10.20.3.4", "host": "APP-PAY-01",
                   "evidence_id": "EVID-ASSET-1"}],
        "processes": [{"host": "APP-PAY-01", "process": "java:payments",
                       "evidence_id": "EVID-RUNTIME-1", "basis": "process-trace"}],
        "apis": [{"process": "java:payments", "api": "PAYMENTS-API",
                  "evidence_id": "EVID-API-1"}],
        "libraries": [{"api": "PAYMENTS-API", "library": "OpenSSL", "version": "3.0.13",
                       "evidence_id": "EVID-RUNTIME-2"}],
        "hsms": [{"library": "OpenSSL", "hsm": "HSM-PAY-01", "key_label": "pin-key-1",
                  "evidence_id": "EVID-KEY-1"}],
    }


def test_sc08_the_path_runs_from_source_address_to_hsm():
    event = sc.collector("IDS", "suricata", ids_feed()).collect_security_events()[0]
    result = sc.correlate_event(event, **correlation_inputs())
    assert result["question"].startswith("What cryptographic assets and critical systems")
    assert result["resolved_hops"] == ["host", "process", "api", "library", "hsm"]
    assert [row["to"] for row in result["path"]] == [
        "APP-PAY-01", "java:payments", "PAYMENTS-API", "OpenSSL", "HSM-PAY-01"]
    assert result["reaches_crypto"] is True
    assert {row["kind"] for row in result["crypto_assets"]} == {"CRYPTO_LIBRARY", "HSM"}
    assert result["answerable"] is True


def test_sc08_the_library_hop_is_runtime_observed_and_the_api_hop_is_configured():
    event = sc.collector("IDS", "suricata", ids_feed()).collect_security_events()[0]
    result = sc.correlate_event(event, **correlation_inputs())
    facts = {row["hop"]: row["fact"] for row in result["path"]}
    assert facts["library"] == sc.RUNTIME_OBSERVED
    assert facts["api"] == sc.CONFIGURED


def test_sc08_an_address_no_inventory_declares_is_a_named_gap():
    event = {"evidence_id": "EVID-IDS-1", "src": "10.99.99.99", "kind": "ALERT"}
    result = sc.correlate_event(event, **correlation_inputs())
    assert result["answerable"] is False
    assert result["reaches_crypto"] is False
    assert result["unresolved"][0]["code"] == "NO_HOST_FOR_ADDRESS"
    assert "10.99.99.99" in result["unresolved"][0]["reason"]


def test_sc08_two_hosts_behind_one_address_is_ambiguous_not_first_row():
    inputs = correlation_inputs()
    inputs["hosts"] = inputs["hosts"] + [{"ip": "10.20.3.4", "host": "APP-PAY-02",
                                          "evidence_id": "EVID-ASSET-2"}]
    result = sc.correlate_event({"src": "10.20.3.4"}, **inputs)
    assert result["unresolved"][0]["code"] == "AMBIGUOUS"
    assert result["unresolved"][0]["candidates"] == ["APP-PAY-01", "APP-PAY-02"]


def test_sc08_the_path_stops_where_the_inventory_does():
    inputs = correlation_inputs()
    inputs["libraries"] = []
    result = sc.correlate_event({"src": "10.20.3.4"}, **inputs)
    assert result["resolved_hops"] == ["host", "process", "api"]
    assert result["unresolved"][0]["code"] == "NO_LIBRARY_FOR_API"
    assert result["reaches_crypto"] is False


# --------------------------------------------------------------------------- #
# SC-09 a control type normalizes what its device actually reports
# --------------------------------------------------------------------------- #

def test_sc09_a_fortigate_accept_is_an_allow_in_the_model():
    collector = sc.collector("FIREWALL", "fortigate", firewall_feed())
    rules = collector.rules()
    assert [row["action"] for row in rules] == ["ALLOW", "DENY"]
    assert rules[0]["service"] == "tcp/HTTPS"
    assert {row["rule"] for row in rules} == {"FW-001", "FW-002"}


def test_sc09_an_incomplete_rule_is_kept_and_marked():
    feed = firewall_feed()
    feed["sections"]["firewall_policy"].append({"srcintf": "guest", "action": "accept"})
    rules = sc.collector("FIREWALL", "fortigate", feed).rules()
    assert rules[-1]["state"] == "INCOMPLETE"


def test_sc09_an_ips_block_is_a_block_and_an_alert_is_not():
    feed = {
        "system": "IPS-01",
        "assets": [{"kind": "IPS", "name": "IPS-01"}],
        "events": [
            {"kind": "BLOCK", "signature": "1:2001", "action": "DROP", "src": "10.0.0.9"},
            {"kind": "ALERT", "signature": "1:2002", "action": "ALERT", "src": "10.0.0.9"},
        ],
        "health": {"reachable": True},
    }
    collector = sc.collector("IPS", "suricata_inline", feed)
    assert len(collector.collect_security_events()) == 2
    assert [row["signature"] for row in collector.blocks()] == ["1:2001"]
    assert collector.enforcement_summary()["blocks"] == 1


def test_sc09_a_load_balancer_flattens_vip_pool_member_with_both_evidence_ids():
    feed = {
        "system": "LB-01",
        "assets": [{"kind": "LOAD_BALANCER", "name": "LB-01"}],
        "sections": {
            "virtual": [{"name": "vs-payments", "destination": "10.30.1.10:443",
                         "pool": "pool-pay", "cert": "CN=payments.internal"}],
            "pool": [{"name": "pool-pay", "membersReference": ["10.30.2.11:8443"]}],
        },
        "health": {"reachable": True},
    }
    collector = sc.collector("LOAD_BALANCER", "f5", feed)
    backends = collector.backends()
    assert backends[0]["vip"] == "vs-payments"
    assert backends[0]["backend"] == "10.30.2.11:8443"
    assert len(backends[0]["evidence_ids"]) == 2


def test_sc09_an_api_gateway_reports_mtls_coverage_without_reading_a_secret():
    feed = {
        "system": "GW-01",
        "assets": [{"kind": "API_GATEWAY", "name": "GW-01"}],
        "sections": {"routes": [
            {"name": "payments", "upstream": "PAYMENTS-API", "mtls": True,
             "client_certificate": "CN=core-banking"},
            {"name": "reports", "upstream": "REPORTS-API", "tls": "NONE",
             "api_secret": "sk-live-xyz"},
        ]},
        "health": {"reachable": True},
    }
    collector = sc.collector("API_GATEWAY", "kong", feed)
    summary = collector.mtls_summary()
    assert summary["mtls_routes"] == ["payments"]
    assert summary["plaintext_routes"] == ["reports"]
    assert "sk-live-xyz" not in json.dumps(collector.snapshot(), default=str)


def test_sc09_a_vpn_tunnel_below_the_crypto_floor_is_reported_not_fixed():
    feed = {
        "system": "VPN-01",
        "assets": [{"kind": "VPN_GATEWAY", "name": "VPN-01"}],
        "sections": {"tunnels": [
            {"conn": "hq", "left": "10.0.0.1", "right": "10.9.0.1", "version": "1",
             "esp": ["3DES"], "hash": ["MD5"], "dh_group": "1024", "pfs": False},
            {"conn": "dr", "left": "10.0.0.1", "right": "10.8.0.1", "version": "2",
             "esp": ["AES256"], "hash": ["SHA256"], "dh_group": "2048", "pfs": True},
        ]},
        "health": {"reachable": True},
    }
    collector = sc.collector("VPN", "strongswan", feed)
    weak = collector.weak_crypto()
    assert [row["tunnel"] for row in weak] == ["hq"]
    assert set(weak[0]["reasons"]) == {"IKEv1", "legacy-algorithm", "dh-group-1024",
                                       "no-pfs"}


def test_sc09_a_siem_event_keeps_its_correlation_reference():
    collector = sc.collector("SIEM", "splunk", events_feed())
    referenced = collector.referenced_events()
    assert referenced[0]["correlated"] is True
    assert referenced[0]["correlation"]["incident_id"] == "INC-77"


# --------------------------------------------------------------------------- #
# SC-10 the registry is a reviewed surface, not a directory listing
# --------------------------------------------------------------------------- #

def test_sc10_every_control_type_is_either_implemented_or_named_as_deferred():
    catalogue = sc.controls()
    assert set(catalogue) == set(sc.CONTROL_TYPES)
    for control, entry in catalogue.items():
        if entry["implemented"]:
            assert len(entry["adapters"]) >= 2, control
            assert entry["collects"] and entry["must_not"], control
        else:
            assert entry["reason"], control


def test_sc10_the_hsm_and_kms_controls_are_named_rather_than_pretended():
    catalogue = sc.controls()
    assert catalogue["HSM"]["implemented"] is False
    assert "hsm_pkcs11" in catalogue["HSM"]["reason"]
    with pytest.raises(sc.ControlRefused) as refused:
        sc.spec_for("KMS", "thales")
    assert refused.value.code == "CONTROL_DEFERRED"


def test_sc10_every_requested_vendor_has_a_dialect():
    expected = {
        "FIREWALL": {"fortigate", "paloalto", "checkpoint", "generic"},
        "IDS": {"snort", "suricata", "vendor"},
        "LOAD_BALANCER": {"f5", "nginx", "haproxy", "avi"},
        "API_GATEWAY": {"kong", "nginx", "envoy", "vendor"},
    }
    for control, vendors in expected.items():
        assert vendors <= set(sc.controls()[control]["adapters"]), control


def test_sc10_an_unknown_vendor_is_refused_with_the_list_of_dialects():
    with pytest.raises(sc.ControlRefused) as refused:
        sc.spec_for("FIREWALL", "netgear")
    assert refused.value.code == "UNKNOWN_VENDOR"
    assert "fortigate" in refused.value.reason


def test_sc10_a_fleet_builds_from_the_same_shape():
    made = sc.fleet([
        {"control": "FIREWALL", "vendor": "fortigate", "feed": firewall_feed()},
        {"control": "IDS", "vendor": "suricata", "feed": ids_feed()},
    ])
    assert [collector.control for collector in made] == ["FIREWALL", "IDS"]
    assert all(collector.read_only for collector in made)


def test_sc10_a_projector_refuses_something_that_is_not_a_collector():
    with pytest.raises(sc.ControlRefused) as refused:
        sc.project([{"assets": []}])
    assert refused.value.code == "NOT_A_COLLECTOR"


# --------------------------------------------------------------------------- #
# SC-11 the health record says what was readable
# --------------------------------------------------------------------------- #

def test_sc11_health_reports_reachability_and_the_read_only_subset():
    collector = sc.collector("FIREWALL", "fortigate", firewall_feed())
    health = collector.health()
    assert health["status"] == "REACHABLE"
    assert health["read_only"] is True
    assert health["operations"] == ["API_GET", "CLI_SHOW"]


def test_sc11_an_unreachable_device_is_unknown_not_healthy():
    feed = firewall_feed()
    feed["health"] = {"reachable": False, "detail": "tcp timeout"}
    health = sc.collector("FIREWALL", "fortigate", feed).health()
    assert health["status"] == "UNREACHABLE"
    assert health["detail"] == "tcp timeout"


def test_sc11_a_device_that_offers_writes_is_flagged_not_trusted():
    feed = firewall_feed()
    feed["health"] = {"reachable": True, "read_only": False}
    collector = sc.collector("FIREWALL", "fortigate", feed)
    health = collector.health()
    assert health["device_offers_writes"] is True
    assert health["read_only"] is True
    assert any(row["code"] == "DEVICE_OFFERS_WRITES" for row in collector.refusals)
