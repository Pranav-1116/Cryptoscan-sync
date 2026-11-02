"""Network crypto assets: the interface owns the hop, not the application behind it.

Review item 8 in one line: a handshake observed on ``payments.bank.example:443``
terminating at ``External LB`` proves the *balancer's* cipher policy. The tests
below are mostly about the attribution rule — when a name may be attached, and
what the module refuses to do with the evidence it is given.
"""

from __future__ import annotations

import pytest

from cbom import network_assets as na

LB_HOP = {
    "from": "Internet", "to": "External LB", "endpoint": "payments.bank.example:443",
    "observed_on": "External LB", "cipher_suite": "TLS_AES_256_GCM_SHA384",
    "tls_version": "1.3", "evidence_id": "NET-9281",
}

APP_HOP = {
    "from": "External LB", "to": "payments-api", "endpoint": "payments-api.internal:8443",
    "observed_on": "payments-api", "cipher_suite": "ECDHE-RSA-AES128-GCM-SHA256",
    "tls_version": "1.2", "evidence_id": "NET-9282",
}


def _one(hop, **kwargs):
    result = na.assets([hop], **kwargs)
    return result["assets"][0], result


# --------------------------------------------------------------------------- #
# the review's five fields


def test_the_review_shape_is_produced_field_for_field():
    asset, _ = _one(LB_HOP)
    assert asset["algorithm"] == "AES-256-GCM"
    assert asset["endpoint"] == "payments.bank.example:443"
    assert asset["observed_on"] == "External LB"
    assert asset["evidence_ids"] == ["NET-9281"]
    assert asset["hop"] == {"from": "Internet", "to": "External LB"}
    assert asset["hop_label"] == "Internet → External LB"


def test_the_terminator_is_classified():
    asset, _ = _one(LB_HOP)
    assert asset["interface_role"] == "LOAD_BALANCER"


@pytest.mark.parametrize("name,role", [
    ("Internet", "UNKNOWN"),
    ("corp-waf-01", "WAF"),
    ("external-lb", "LOAD_BALANCER"),
    ("edge-lb-1", "LOAD_BALANCER"),
    ("api-gateway", "API_GATEWAY"),
    ("envoy-proxy", "REVERSE_PROXY"),
    ("cdn-edge", "CDN"),
    ("payments-api", "UNKNOWN"),
])
def test_a_hop_is_named_from_its_name_only_where_the_name_is_explicit(name, role):
    assert na.hop_role(name) == role


def test_an_explicit_role_wins_over_the_name():
    assert na.hop_role("payments-api", role="APPLICATION") == "APPLICATION"
    assert na.hop_role("odd-name", role="waf") == "WAF"


def test_an_unknown_explicit_role_falls_back_to_the_name():
    assert na.hop_role("corp-waf-01", role="SOMETHING_ELSE") == "WAF"


# --------------------------------------------------------------------------- #
# the attribution rule


def test_a_fronting_hop_is_not_attributed_to_an_application():
    asset, result = _one(LB_HOP, applications=["payments-api"])
    assert asset["algorithm"] == "AES-256-GCM"
    assert asset["application"] is None
    assert asset["application_inference"] == "NOT_PROVEN"
    # the suite names AES-256-GCM and SHA-384; both belong to the interface
    assert result["unattributed_to_an_application"] == 2


def test_the_statement_says_the_asset_belongs_to_the_interface():
    asset, _ = _one(LB_HOP)
    assert "interface fact" in asset["statement"]
    assert "not attributed to any application" in asset["statement"]


def test_a_declared_application_terminates_its_own_hop():
    asset, _ = _one(APP_HOP, applications=["payments-api"])
    assert asset["application"] == "payments-api"
    assert asset["application_inference"] == "PROVEN"
    assert asset["interface_role"] == "APPLICATION"


def test_an_undeclared_application_name_is_not_taken_on_trust():
    asset, _ = _one(APP_HOP)
    assert asset["application"] is None
    assert asset["application_inference"] == "NOT_PROVEN"


def test_a_hop_that_declares_itself_an_application_needs_no_estate_declaration():
    asset, _ = _one({**APP_HOP, "role": "APPLICATION"})
    assert asset["application_inference"] == "PROVEN"


def test_an_application_hop_never_absorbs_a_fronting_hop_in_the_same_run():
    result = na.assets([LB_HOP, APP_HOP], applications=["payments-api"])
    by_endpoint = {(row["endpoint"], row["algorithm"]): row for row in result["assets"]}
    aes = by_endpoint[("payments.bank.example:443", "AES-256-GCM")]
    bulk = by_endpoint[("payments-api.internal:8443", "AES-128-GCM")]
    assert aes["application"] is None and aes["application_inference"] == "NOT_PROVEN"
    assert bulk["application"] == "payments-api"
    assert result["unattributed_to_an_application"] == len(result["assets"]) - 4


# --------------------------------------------------------------------------- #
# one asset per endpoint and algorithm


def test_the_bulk_cipher_of_an_openssl_suite_is_not_lost():
    algorithms = {row["algorithm"] for row in na.assets([APP_HOP])["assets"]}
    assert algorithms == {"AES-128-GCM", "ECDHE", "RSA", "SHA-256"}


def test_two_endpoints_negotiating_the_same_suite_are_two_assets():
    second = {**LB_HOP, "endpoint": "openbanking.bank.example:443",
              "evidence_id": "NET-9283"}
    result = na.assets([LB_HOP, second])
    assert len(result["assets"]) == 4
    assert [row["endpoint"] for row in result["assets"]] == [
        "openbanking.bank.example:443", "openbanking.bank.example:443",
        "payments.bank.example:443", "payments.bank.example:443"]


def test_repeated_observations_merge_their_evidence():
    repeat = {**LB_HOP, "evidence_id": "NET-9290"}
    result = na.assets([LB_HOP, repeat])
    aes = [row for row in result["assets"] if row["algorithm"] == "AES-256-GCM"][0]
    assert aes["evidence_ids"] == ["NET-9281", "NET-9290"]


def test_a_hop_that_upgrades_its_tls_version_records_both():
    repeat = {**LB_HOP, "evidence_id": "NET-9291", "tls_version": "1.2"}
    result = na.assets([LB_HOP, repeat])
    aes = [row for row in result["assets"] if row["algorithm"] == "AES-256-GCM"][0]
    assert aes["tls_versions"] == ["1.2", "1.3"]


def test_the_role_inside_the_suite_is_kept():
    result = na.assets([APP_HOP])
    roles = {row["algorithm"]: row["role_in_suite"] for row in result["assets"]}
    assert roles["AES-128-GCM"] == "BULK"
    assert roles["ECDHE"] == "KEY_EXCHANGE"


# --------------------------------------------------------------------------- #
# refusals


def test_a_hop_with_no_endpoint_is_refused():
    result = na.assets([{**LB_HOP, "endpoint": None}])
    assert result["assets"] == []
    assert "endpoint" in result["refused"][0]["reason"]


def test_a_hop_with_no_negotiated_suite_attributes_no_algorithm():
    result = na.assets([{**LB_HOP, "cipher_suite": None}])
    assert result["assets"] == []
    assert "suite" in result["refused"][0]["reason"]


def test_a_hop_with_no_evidence_id_attributes_nothing():
    result = na.assets([{**LB_HOP, "evidence_id": None}])
    assert result["assets"] == []
    assert "evidence id" in result["refused"][0]["reason"]


def test_a_hop_with_no_observer_is_refused_because_a_path_position_is_not_an_owner():
    result = na.assets([{**LB_HOP, "observed_on": None, "to": None}])
    assert result["assets"] == []
    assert "owner" in result["refused"][0]["reason"] or "no interface" in \
        result["refused"][0]["reason"]


def test_a_hop_that_is_not_an_object_is_refused():
    result = na.assets(["External LB"])
    assert result["refused"][0]["reason"] == "a hop must be an object"


def test_the_observed_on_falls_back_to_the_hop_target():
    asset, _ = _one({**LB_HOP, "observed_on": None})
    assert asset["observed_on"] == "External LB"


# --------------------------------------------------------------------------- #
# the document


def test_a_network_component_is_one_per_endpoint_and_algorithm():
    result = na.assets([LB_HOP, APP_HOP], applications=["payments-api"])
    components = na.to_components(result)["components"]
    refs = [component["bom-ref"] for component in components]
    assert len(refs) == len(set(refs)) == len(result["assets"])
    assert "network:payments.bank.example:443#AES-256-GCM" in refs


def test_a_network_component_carries_the_five_fields_as_properties():
    component = na.to_components(na.assets([LB_HOP]))["components"][0]
    properties = {row["name"]: row["value"] for row in component["properties"]}
    assert properties["cryptoscan:endpoint"] == "payments.bank.example:443"
    assert properties["cryptoscan:observed_on"] == "External LB"
    assert properties["cryptoscan:hop"] == "Internet → External LB"
    assert properties["cryptoscan:evidence_id"] == "NET-9281"
    assert properties["cryptoscan:network_observed"] == "true"


def test_a_network_component_writes_no_application_it_cannot_prove():
    component = na.to_components(na.assets([LB_HOP],
                                           applications=["payments-api"]))["components"][0]
    names = {row["name"] for row in component["properties"]}
    assert "cryptoscan:application" not in names
    assert "cryptoscan:application_inference" in names


def test_a_proven_application_is_written_down():
    component = na.to_components(
        na.assets([APP_HOP], applications=["payments-api"]))["components"][0]
    properties = {row["name"]: row["value"] for row in component["properties"]}
    assert properties["cryptoscan:application"] == "payments-api"
    assert properties["cryptoscan:application_inference"] == "PROVEN"


def test_a_network_component_is_a_cyclonedx_cryptographic_asset():
    component = na.to_components(na.assets([LB_HOP]))["components"][0]
    assert component["type"] == "cryptographic-asset"
    assert component["cryptoProperties"]["assetType"] == "algorithm"
    assert component["cryptoProperties"]["algorithmProperties"]["parameterSetIdentifier"] == "256"


# --------------------------------------------------------------------------- #
# the overclaim audit


def _graph(*edges):
    return {"edges": list(edges)}


def test_an_application_edge_resting_on_a_fronting_hop_is_an_overclaim():
    result = na.assets([LB_HOP], applications=["payments-api"])
    audit = na.audit_graph(_graph({
        "from": "application:payments-api", "kind": "USES_CRYPTO",
        "to": "algorithm:AES-256-GCM", "classes": ["NETWORK_OBSERVED"],
        "evidence_ids": ["NET-9281"]}), result)
    assert len(audit["overclaims"]) == 1
    claim = audit["overclaims"][0]
    assert claim["terminated_at"] == ["External LB"]
    assert claim["interface_roles"] == ["LOAD_BALANCER"]
    assert "in front of" in claim["reason"]


def test_a_system_edge_is_audited_too():
    result = na.assets([LB_HOP])
    audit = na.audit_graph(_graph({
        "from": "system:bank-estate", "kind": "USES_CRYPTO",
        "to": "algorithm:AES-256-GCM", "classes": ["NETWORK_OBSERVED"]}), result)
    assert audit["overclaims"][0]["subject"] == "system:bank-estate"


def test_the_graphs_own_class_key_is_read():
    """``usage_graph`` names the field ``evidence_classes``; the audit must read the
    graph it is given rather than a shape it expects."""
    result = na.assets([LB_HOP])
    audit = na.audit_graph(_graph({
        "from": "system:bank-estate", "kind": "USES_CRYPTO",
        "to": "algorithm:AES-256-GCM", "evidence_classes": ["NETWORK_OBSERVED"]}), result)
    assert len(audit["overclaims"]) == 1


def test_an_edge_backed_by_runtime_evidence_is_not_an_overclaim():
    result = na.assets([LB_HOP])
    audit = na.audit_graph(_graph({
        "from": "application:payments-api", "kind": "USES_CRYPTO",
        "to": "algorithm:AES-256-GCM", "classes": ["RUNTIME_OBSERVED", "NETWORK_OBSERVED"]}),
        result)
    assert audit["overclaims"] == []


def test_an_edge_to_an_algorithm_the_network_never_saw_is_not_audited():
    result = na.assets([LB_HOP])
    audit = na.audit_graph(_graph({
        "from": "application:payments-api", "kind": "USES_CRYPTO",
        "to": "algorithm:SHA-1", "classes": ["RUNTIME_OBSERVED"]}), result)
    assert audit["checked_edges"] == 0
    assert audit["overclaims"] == []


def test_a_proven_application_terminating_the_hop_is_not_an_overclaim():
    result = na.assets([APP_HOP], applications=["payments-api"])
    audit = na.audit_graph(_graph({
        "from": "application:payments-api", "kind": "USES_CRYPTO",
        "to": "algorithm:AES-128-GCM", "classes": ["NETWORK_OBSERVED"]}), result)
    assert audit["overclaims"] == []


def test_edges_of_another_kind_are_ignored():
    result = na.assets([LB_HOP])
    audit = na.audit_graph(_graph({
        "from": "application:payments-api", "kind": "NEGOTIATES",
        "to": "algorithm:AES-256-GCM", "classes": ["NETWORK_OBSERVED"]}), result)
    assert audit["checked_edges"] == 0


# --------------------------------------------------------------------------- #
# the summary


def test_the_summary_counts_what_was_attributed_and_what_was_not():
    result = na.assets([LB_HOP, APP_HOP], applications=["payments-api"])
    summary = na.summary(result)
    assert summary["endpoints"] == 2
    assert summary["interfaces"] == 2
    assert summary["attributed_to_an_application"] == 4
    assert len(summary["not_attributed"]) == 2
    assert "left with the interface that terminated them" in summary["statement"]


def test_the_estate_summary_of_nothing_is_empty_not_wrong():
    summary = na.summary(na.assets([]))
    assert summary["assets"] == 0
    assert summary["refused"] == 0
    assert summary["algorithms"] == []
