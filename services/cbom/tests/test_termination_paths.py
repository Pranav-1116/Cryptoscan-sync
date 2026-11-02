"""TLS termination as a path: three relationships, never one attribute.

The review's item 9 draws a client → LB → gateway → application chain where the
middle hop is weaker than both ends. These tests are about keeping the three
relationships apart, naming the downgrade, and refusing the merged claim.
"""

from __future__ import annotations

from cbom import termination_paths as tp

CLIENT_LB = {"from": "Client", "to": "External LB", "observed_on": "External LB",
             "endpoint": "payments.bank.example:443", "tls_version": "1.3",
             "cipher_suite": "TLS_AES_256_GCM_SHA384", "evidence_id": "NET-1"}
LB_GATEWAY = {"from": "External LB", "to": "API Gateway", "observed_on": "External LB",
              "endpoint": "gateway.bank.example:443", "tls_version": "1.2",
              "cipher_suite": "ECDHE-RSA-AES128-GCM-SHA256", "evidence_id": "NET-2"}
GATEWAY_APP = {"from": "API Gateway", "to": "Payments API", "observed_on": "API Gateway",
               "endpoint": "payments-api.internal:8443", "tls_version": "1.3",
               "cipher_suite": "TLS_AES_256_GCM_SHA384", "evidence_id": "NET-3"}


def _path():
    return tp.build([CLIENT_LB, LB_GATEWAY, GATEWAY_APP])


# --------------------------------------------------------------------------- #
# the three relationships


def test_the_path_is_three_relationships_not_one_attribute():
    result = _path()
    assert len(result["paths"]) == 1
    assert len(result["paths"][0]["hops"]) == 3
    assert len(result["relationships"]) == 3


def test_the_nodes_are_in_order():
    nodes = _path()["paths"][0]["nodes"]
    assert nodes == ["Client", "External LB", "API Gateway", "Payments API"]


def test_each_relationship_carries_its_own_version_suite_and_evidence():
    rows = _path()["relationships"]
    assert [row["tls_version"] for row in rows] == ["1.3", "1.2", "1.3"]
    assert rows[0]["evidence_ids"] == ["NET-1"]
    assert rows[1]["evidence_ids"] == ["NET-2"]
    assert rows[1]["cipher_suite"] == "ECDHE-RSA-AES128-GCM-SHA256"


def test_the_middle_hop_keeps_its_own_algorithms():
    rows = _path()["relationships"]
    assert "AES-128-GCM" in rows[1]["algorithms"]
    assert "AES-128-GCM" not in rows[0]["algorithms"]
    assert "AES-128-GCM" not in rows[2]["algorithms"]


def test_a_relationship_statement_names_the_hop_it_belongs_to():
    statement = _path()["relationships"][1]["statement"]
    assert statement.startswith("External LB → API Gateway")
    assert "TLS 1.2" in statement and "AES-128-GCM" in statement


def test_the_path_statement_counts_the_relationships():
    assert "3 cryptographic relationship(s)" in _path()["paths"][0]["statement"]
    assert "each hop is a separate fact" in _path()["paths"][0]["statement"]


# --------------------------------------------------------------------------- #
# the change between hops is the finding


def test_the_downgrade_in_the_middle_is_named():
    result = _path()
    assert len(result["downgrades"]) == 1
    downgrade = result["downgrades"][0]
    assert downgrade["kind"] == "TLS_VERSION_DOWNGRADE"
    assert downgrade["from_hop"] == 1 and downgrade["to_hop"] == 2
    assert downgrade["detail"] == "TLS 1.2 after TLS 1.3"


def test_the_upgrade_after_the_downgrade_is_reported_too():
    kinds = [change["kind"] for change in _path()["changes"]]
    assert "TLS_VERSION_UPGRADE" in kinds


def test_the_bulk_cipher_change_is_reported_not_the_whole_suite():
    kinds = [change["kind"] for change in _path()["changes"]]
    assert "BULK_CIPHER_CHANGED" in kinds
    detail = [change["detail"] for change in _path()["changes"]
              if change["kind"] == "BULK_CIPHER_CHANGED"][0]
    assert detail == "['AES-128-GCM'] after ['AES-256-GCM']"


def test_a_same_version_hop_with_a_different_suite_is_a_suite_change():
    stricter = {**CLIENT_LB, "from": "External LB", "to": "API Gateway",
                "cipher_suite": "ECDHE-ECDSA-AES256-GCM-SHA384", "evidence_id": "NET-9"}
    result = tp.build([CLIENT_LB, stricter])
    assert [change["kind"] for change in result["changes"]] == ["SUITE_CHANGED"]


def test_the_bulk_cipher_is_compared_not_the_suite_length():
    """A TLS 1.3 suite names two algorithms and a TLS 1.2 suite four; comparing the
    whole list would report a change on every hop. The bulk cipher is the fact."""
    wide = {**CLIENT_LB, "cipher_suite": "ECDHE-RSA-AES128-GCM-SHA256"}
    narrow = {**LB_GATEWAY, "tls_version": "1.3", "cipher_suite": "TLS_AES_256_GCM_SHA384"}
    result = tp.build([wide, narrow])
    kinds = [change["kind"] for change in result["changes"]]
    assert kinds == ["BULK_CIPHER_CHANGED"]


def test_version_spellings_rank_the_same():
    for spelling in ("TLSv1.2", "TLS1.2", "1.2", "tlsv1.2"):
        hop = {**LB_GATEWAY, "tls_version": spelling,
               "cipher_suite": "TLS_AES_256_GCM_SHA384"}
        other = {**GATEWAY_APP, "from": "API Gateway", "to": "X", "tls_version": "1.3"}
        result = tp.build([hop, other])
        assert "TLS_VERSION_UPGRADE" in [change["kind"]
                                         for change in result["changes"]], spelling


def test_an_unparseable_version_does_not_invent_a_downgrade():
    hop = {**CLIENT_LB, "tls_version": "SSLV3"}
    result = tp.build([hop, LB_GATEWAY])
    assert result["downgrades"] == []


# --------------------------------------------------------------------------- #
# the merged claim


def test_the_merged_claim_is_computed_and_refused():
    merged = _path()["merged"]
    assert merged["refused"] is True
    assert merged["hops_differ"] is True
    assert "AES-128-GCM" in merged["algorithms"] and "AES-256-GCM" in merged["algorithms"]
    assert "describes no hop" in merged["statement"]


def test_there_is_nothing_to_collapse_without_a_path():
    merged = tp.build([])["merged"]
    assert merged["refused"] is False
    assert merged["statement"] == "there is no path to collapse"


def test_one_hop_cannot_differ_from_itself():
    merged = tp.build([CLIENT_LB])["merged"]
    assert merged["hops_differ"] is False


# --------------------------------------------------------------------------- #
# gaps and refusals


def test_a_hop_with_no_connector_is_a_gap_not_a_path():
    orphan = {**GATEWAY_APP, "from": "Somewhere"}
    result = tp.build([CLIENT_LB, orphan])
    assert len(result["paths"]) == 2
    assert len(result["gaps"]) == 2
    assert "not invented" in result["gaps"][0]["reason"]


def test_a_connected_chain_has_no_gaps():
    assert _path()["gaps"] == []


def test_a_hop_with_no_start_node_is_refused():
    result = tp.build([{key: value for key, value in CLIENT_LB.items() if key != "from"}])
    assert result["relationships"] == []
    assert "starts from" in result["refused"][0]["reason"]


def test_a_hop_with_no_reached_node_is_refused():
    hop = {key: value for key, value in CLIENT_LB.items()
           if key not in ("to", "observed_on")}
    result = tp.build([hop])
    assert "reaches" in result["refused"][0]["reason"]


def test_a_hop_with_no_suite_is_refused():
    result = tp.build([{key: value for key, value in CLIENT_LB.items()
                        if key != "cipher_suite"}])
    assert "negotiated suite" in result["refused"][0]["reason"]


def test_a_hop_with_no_evidence_is_refused():
    result = tp.build([{**CLIENT_LB, "evidence_id": None}])
    assert "evidence id" in result["refused"][0]["reason"]


def test_a_hop_that_is_not_an_object_is_refused():
    result = tp.build(["Client"])
    assert result["refused"][0]["reason"] == "a hop must be an object"


# --------------------------------------------------------------------------- #
# pass-through and modes


def test_a_tunnelling_hop_passes_through_and_terminates_nothing():
    result = tp.build([{**CLIENT_LB, "terminates": False}])
    relationship = result["relationships"][0]
    assert relationship["mode"] == "PASSES_THROUGH"
    assert relationship["terminated_at"] is None


def test_an_explicit_mode_is_honoured():
    result = tp.build([{**CLIENT_LB, "mode": "passes_through"}])
    assert result["relationships"][0]["mode"] == "PASSES_THROUGH"


def test_an_unknown_mode_falls_back_to_the_terminates_flag():
    result = tp.build([{**CLIENT_LB, "mode": "whatever"}])
    assert result["relationships"][0]["mode"] == "TERMINATES"


# --------------------------------------------------------------------------- #
# the document


def test_one_component_per_path_hop_and_algorithm():
    result = _path()
    components = tp.to_components(result)["components"]
    # 2 + 4 + 2 algorithms across the three hops
    assert len(components) == 8
    refs = {component["bom-ref"] for component in components}
    assert "path:1#hop:2#AES-128-GCM" in refs


def test_a_component_names_its_hop_and_version():
    component = [row for row in tp.to_components(_path())["components"]
                 if row["bom-ref"] == "path:1#hop:2#AES-128-GCM"][0]
    properties = {row["name"]: row["value"] for row in component["properties"]}
    assert properties["cryptoscan:from"] == "External LB"
    assert properties["cryptoscan:to"] == "API Gateway"
    assert properties["cryptoscan:tls_version"] == "1.2"
    assert properties["cryptoscan:evidence_id"] == "NET-2"


def test_no_component_names_an_application():
    for component in tp.to_components(_path())["components"]:
        names = {row["name"] for row in component["properties"]}
        assert "cryptoscan:application" not in names


# --------------------------------------------------------------------------- #
# the edges


def test_an_algorithm_edge_belongs_to_its_hop():
    edges = tp.to_edges(_path())["edges"]
    sources = {edge["from"] for edge in edges if edge["kind"] == "NEGOTIATES"}
    assert sources == {"hop:Client→External LB", "hop:External LB→API Gateway",
                       "hop:API Gateway→Payments API"}
    assert not any(edge["from"].startswith(("application:", "system:", "host:"))
                   for edge in edges)


def test_the_hops_are_ordered_by_precedes_edges():
    edges = tp.to_edges(_path())["edges"]
    precedes = [(edge["from"], edge["to"]) for edge in edges
                if edge["kind"] == "PRECEDES"]
    assert precedes == [
        ("hop:Client→External LB", "hop:External LB→API Gateway"),
        ("hop:External LB→API Gateway", "hop:API Gateway→Payments API"),
    ]


def test_every_edge_is_network_observed():
    for edge in tp.to_edges(_path())["edges"]:
        assert edge["provenance"] == "OBSERVED"
        assert edge["classes"] == ["NETWORK_OBSERVED"]
        assert edge["evidence_ids"]


# --------------------------------------------------------------------------- #
# the summary


def test_the_summary_counts_relationships_and_downgrades():
    summary = tp.summary(_path())
    assert summary["paths"] == 1
    assert summary["relationships"] == 3
    assert summary["downgrades"] == 1
    assert summary["weakest_hops"] == ["path 1 hop 2: TLS 1.2 after TLS 1.3"]
    assert summary["merge_refused"] is True


def test_the_summary_of_nothing_is_empty_not_wrong():
    summary = tp.summary(tp.build([]))
    assert summary["paths"] == 0 and summary["relationships"] == 0
    assert summary["merge_refused"] is False
    assert "0 cryptographic relationship(s)" in summary["statement"]
