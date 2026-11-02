"""NBOM coverage: an observed endpoint is not the network.

Review item 4's example is the specification: 10,000 expected, 8,000 attempted,
6,500 observed, 1,000 failed, 500 unauthorized is 65%, ``PARTIAL``, and any count
derived from it is a floor.
"""

from __future__ import annotations

import pytest

from cbom import nbom_coverage as nc

MATRIX = [
    {"target": "External endpoints", "expected": 120, "attempted": 120, "observed": 118},
    {"target": "Internal LB", "expected": 25, "attempted": 25, "observed": 25},
    {"target": "API gateways", "expected": 40, "attempted": 40, "observed": 37},
    {"target": "DB endpoints", "expected": 80, "attempted": 60, "observed": 54},
    {"target": "HSM network interfaces", "expected": 8, "attempted": 8, "observed": 8},
    {"target": "VPN gateways", "expected": 12, "attempted": 10, "observed": 9},
]


def _estate():
    return {"target": "all endpoints", "expected": 10000, "attempted": 8000,
            "observed": 6500, "failed": 1000, "unauthorized": 500}


# --------------------------------------------------------------------------- #
# the review's own numbers


def test_the_review_example_is_65_percent_and_partial():
    block = nc.matrix([_estate()])
    assert block["coverage_pct"] == 65.0
    assert block["status"] == "PARTIAL"
    assert block["totals"]["observed"] == 6500
    assert block["totals"]["expected"] == 10000


def test_the_endpoints_nobody_planned_are_counted_not_ignored():
    row = nc.matrix([_estate()])["groups"][0]
    assert row["unattempted"] == 1500  # 10,000 − 8,000 − 500 unauthorized
    assert "1500 never attempted" in row["statement"]


def test_a_partial_estate_supports_a_floor_and_never_a_total():
    claim = nc.matrix([_estate()])["claim"]
    assert claim["basis"] == "FLOOR"
    assert claim["may_report_total"] is False
    assert "is a floor" in claim["statement"]


def test_the_statement_names_every_gap():
    statement = nc.matrix([_estate()])["statement"]
    for fragment in ("1500 never attempted", "500 unauthorized", "1000 failed",
                     "floor on the network"):
        assert fragment in statement


# --------------------------------------------------------------------------- #
# five statuses, because "not complete" is too coarse


def test_a_fully_observed_group_is_complete():
    block = nc.matrix([{"target": "Internal LB", "expected": 25, "attempted": 25,
                        "observed": 25}])
    assert block["groups"][0]["status"] == "COMPLETE"
    assert block["status"] == "COMPLETE"


def test_a_group_nobody_inventoried_is_unmeasured_not_complete():
    block = nc.matrix([{"target": "Partner network", "expected": 0}])
    row = block["groups"][0]
    assert row["status"] == "UNMEASURED"
    assert row["reasons"] == ["NO_TARGETS"]
    assert row["coverage_pct"] is None
    assert "0% and 100% are both wrong" in row["statement"]
    assert block["claim"]["basis"] == "UNKNOWN"


def test_probes_that_all_failed_are_a_scan_failure_not_an_empty_network():
    block = nc.matrix([{"target": "DMZ", "expected": 10, "attempted": 10, "observed": 0,
                        "failed": 10}])
    assert block["groups"][0]["status"] == "FAILED"
    assert "scan failure, not an empty network" in block["groups"][0]["statement"]


def test_a_group_with_nothing_attempted_for_authorization_is_unauthorized():
    block = nc.matrix([{"target": "Partner VPN", "expected": 12, "attempted": 0,
                        "observed": 0, "unauthorized": 12}])
    assert block["groups"][0]["status"] == "UNAUTHORIZED"
    assert "not authorized" in block["groups"][0]["statement"]


def test_a_group_that_was_never_attempted_is_partial_and_says_so():
    row = nc.matrix([{"target": "DB", "expected": 80, "attempted": 0, "observed": 0}])["groups"][0]
    assert row["status"] == "PARTIAL"
    assert row["reasons"] == ["NOT_ATTEMPTED"]


def test_the_estate_is_complete_only_when_every_group_is():
    block = nc.matrix([{"target": "a", "expected": 2, "attempted": 2, "observed": 2},
                       {"target": "b", "expected": 3, "attempted": 3, "observed": 2}])
    assert block["status"] == "PARTIAL"
    assert block["complete_groups"] == ["a"]
    assert block["incomplete_groups"] == ["b"]


def test_an_unmeasured_group_keeps_the_estate_from_being_complete():
    block = nc.matrix([{"target": "a", "expected": 2, "attempted": 2, "observed": 2},
                       {"target": "b", "expected": 0}])
    assert block["status"] == "PARTIAL"
    assert block["unmeasured_groups"] == ["b"]
    assert block["claim"]["may_report_total"] is False


def test_an_estate_where_everything_failed_is_failed_overall():
    block = nc.matrix([{"target": "a", "expected": 2, "attempted": 2, "observed": 0,
                        "failed": 2},
                       {"target": "b", "expected": 2, "attempted": 2, "observed": 0,
                        "failed": 2}])
    assert block["status"] == "FAILED"


def test_a_complete_estate_is_the_only_estate_that_supports_a_total():
    block = nc.matrix([{"target": "a", "expected": 2, "attempted": 2, "observed": 2},
                       {"target": "b", "expected": 3, "attempted": 3, "observed": 3}])
    assert block["status"] == "COMPLETE"
    claim = block["claim"]
    assert claim["may_report_total"] is True and claim["basis"] == "TOTAL"
    assert "every expected endpoint was observed" in claim["statement"]


# --------------------------------------------------------------------------- #
# the arithmetic is checked, not clamped


def test_observing_more_than_expected_is_refused():
    with pytest.raises(ValueError, match="target list is stale"):
        nc.matrix([{"target": "x", "expected": 5, "attempted": 5, "observed": 6}])


def test_attempting_more_than_expected_is_refused():
    with pytest.raises(ValueError, match="nobody inventoried"):
        nc.matrix([{"target": "x", "expected": 5, "attempted": 6, "observed": 1}])


def test_observing_more_than_was_attempted_is_refused():
    with pytest.raises(ValueError, match="an observation needs a probe"):
        nc.matrix([{"target": "x", "expected": 5, "attempted": 1, "observed": 2}])


def test_a_negative_count_is_refused():
    with pytest.raises(ValueError, match="cannot be negative"):
        nc.matrix([{"target": "x", "expected": -1}])


def test_a_boolean_is_not_a_count():
    with pytest.raises(ValueError, match="not a boolean"):
        nc.matrix([{"target": "x", "expected": True}])


def test_a_row_with_no_target_is_refused():
    with pytest.raises(ValueError, match="needs a target"):
        nc.matrix([{"expected": 5}])


def test_the_same_group_twice_is_refused_rather_than_summed():
    with pytest.raises(ValueError, match="appears twice"):
        nc.matrix([{"target": "DMZ", "expected": 1},
                   {"target": "dmz", "expected": 1}])


def test_a_row_that_is_not_an_object_is_refused():
    with pytest.raises(ValueError, match="must be an object"):
        nc.matrix(["External endpoints"])


# --------------------------------------------------------------------------- #
# stored probes


def test_an_unknown_probe_status_is_refused_not_bucketed():
    body = nc.from_probes("External", [{"endpoint": "a:443", "status": "OK"},
                                       {"endpoint": "b:443", "status": "MAYBE"}])
    assert body["row"]["observed"] == 1
    assert body["refused"][0]["status"] == "MAYBE"
    assert "not a documented probe outcome" in body["refused"][0]["reason"]


def test_a_timeout_is_a_failure_and_never_an_observation():
    body = nc.from_probes("External", [{"endpoint": "a:443", "status": "TIMEOUT"}])
    row = body["row"]
    assert row["observed"] == 0 and row["failed"] == 1
    assert "plaintext" not in body["statement"].lower()


def test_a_declared_endpoint_nobody_probed_widens_the_target_list():
    body = nc.from_probes("External", [{"endpoint": "a:443", "status": "OK"}],
                          declared=["a:443", "b:443", "c:443"])
    row = body["row"]
    assert row["expected"] == 3
    assert row["unattempted"] == 2
    assert row["declared_not_probed"] == ["b:443", "c:443"]
    assert "never probed" in body["statement"]


def test_an_endpoint_probed_but_never_declared_still_counts():
    body = nc.from_probes("External", [{"endpoint": "z:443", "status": "OK"}],
                          declared=["a:443"])
    assert body["row"]["expected"] == 2


def test_an_unauthorized_probe_is_not_counted_as_attempted():
    body = nc.from_probes("Partner", [{"endpoint": "a:443", "status": "UNAUTHORIZED"}])
    row = body["row"]
    assert row["unauthorized"] == 1 and row["attempted"] == 0
    assert row["status"] == "UNAUTHORIZED"


def test_a_probe_with_no_endpoint_is_refused():
    body = nc.from_probes("External", [{"status": "OK"}])
    assert "no endpoint" in body["refused"][0]["reason"]


# --------------------------------------------------------------------------- #
# the document


def _bom():
    return {"bomFormat": "CycloneDX", "specVersion": "1.5",
            "components": [{"type": "network-endpoint", "bom-ref": "endpoint:1",
                            "name": "a:443"}],
            "metadata": {"properties": [{"name": "cryptoscan:estate", "value": "x"}]}}


def test_attaching_coverage_writes_the_claim_into_the_document():
    block = nc.matrix([_estate()])
    document = nc.attach(_bom(), block)
    properties = {row["name"]: row["value"]
                  for row in document["metadata"]["properties"]}
    assert properties[nc.PROPERTY_STATUS] == "PARTIAL"
    assert properties[nc.PROPERTY_PCT] == "65.0"
    assert properties[nc.PROPERTY_EXPECTED] == "10000"
    assert properties[nc.PROPERTY_OBSERVED] == "6500"
    assert properties[nc.PROPERTY_TOTAL] == "false"
    assert "cryptoscan:estate" in properties  # existing properties survive


def test_attaching_twice_replaces_the_block_instead_of_duplicating_it():
    block = nc.matrix([_estate()])
    document = nc.attach(nc.attach(_bom(), block), block)
    names = [row["name"] for row in document["metadata"]["properties"]]
    assert names.count(nc.PROPERTY_STATUS) == 1


def test_an_nbom_with_components_and_no_coverage_is_unqualified():
    verdict = nc.qualify(_bom())
    assert verdict["state"] == "UNQUALIFIED"
    assert verdict["ok"] is False
    assert "does not say how much of the network" in verdict["statement"]


def test_an_empty_nbom_claims_nothing_and_is_not_unqualified():
    verdict = nc.qualify({"components": [], "metadata": {}})
    assert verdict["state"] == "EMPTY" and verdict["ok"] is True


def test_a_qualified_document_says_whether_a_total_may_be_quoted():
    block = nc.matrix([{"target": "a", "expected": 2, "attempted": 2, "observed": 2}])
    verdict = nc.qualify(nc.attach(_bom(), block))
    assert verdict["state"] == "COMPLETE"
    assert verdict["may_report_total"] is True
    assert "may be quoted" in verdict["statement"]


def test_the_matrix_carries_its_own_as_of_and_unit():
    block = nc.matrix(MATRIX, as_of="2026-11-02", unit="listener")
    assert block["as_of"] == "2026-11-02"
    assert block["unit"] == "listener"
    assert block["totals"]["expected"] == 285


def test_the_summary_reports_gaps_without_hiding_behind_a_percentage():
    block = nc.matrix(MATRIX)
    summary = nc.summary(block)
    assert summary["coverage_pct"] == 88.1
    assert summary["gaps"]["unattempted"] == 22
    assert summary["may_report_total"] is False
    assert summary["complete_groups"] == ["Internal LB", "HSM network interfaces"]
