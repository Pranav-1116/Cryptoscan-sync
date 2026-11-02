"""NBOM coverage over HTTP: the matrix, and a probe ledger that refuses to guess.

Review item 4 is about what a document may imply, so these tests check the response
rather than only the arithmetic: 65% is `PARTIAL`, the claim is a `FLOOR`, and a
probe with an undocumented status is refused instead of counted.
"""

from __future__ import annotations

import pytest

ESTATE_GROUPS = [{"target": "all endpoints", "expected": 10000, "attempted": 8000,
                  "observed": 6500, "failed": 1000, "unauthorized": 500}]

#: The coverage routes are role-gated and require a credential-bearing request.
AUTH = {"Authorization": "Bearer test-token"}


@pytest.mark.asyncio
async def test_coverage_of_a_partial_estate_is_a_floor(authenticated_client):
    response = await authenticated_client.post("/api/v1/cbom/nbom/coverage",
                                               json={"groups": ESTATE_GROUPS}, headers=AUTH)
    assert response.status_code == 200
    body = response.json()
    assert body["coverage_pct"] == 65.0
    assert body["status"] == "PARTIAL"
    assert body["claim"]["basis"] == "FLOOR"
    assert body["claim"]["may_report_total"] is False
    assert body["totals"]["unattempted"] == 1500
    assert body["summary"]["may_report_total"] is False


@pytest.mark.asyncio
async def test_a_complete_estate_may_report_a_total(authenticated_client):
    response = await authenticated_client.post("/api/v1/cbom/nbom/coverage", json={
        "groups": [{"target": "Internal LB", "expected": 25, "attempted": 25,
                    "observed": 25}]}, headers=AUTH)
    body = response.json()
    assert body["status"] == "COMPLETE"
    assert body["claim"]["may_report_total"] is True
    assert body["claim"]["basis"] == "TOTAL"


@pytest.mark.asyncio
async def test_an_estate_with_no_target_list_is_unmeasured_not_complete(
        authenticated_client):
    response = await authenticated_client.post("/api/v1/cbom/nbom/coverage",
                                               json={"groups": [{"target": "Partner",
                                                                 "expected": 0}]},
                                               headers=AUTH)
    body = response.json()
    assert body["status"] == "UNMEASURED"
    assert body["coverage_pct"] is None
    assert body["claim"]["basis"] == "UNKNOWN"
    assert body["unmeasured_groups"] == ["Partner"]


@pytest.mark.asyncio
async def test_a_stale_target_list_is_refused_with_the_reason(authenticated_client):
    response = await authenticated_client.post("/api/v1/cbom/nbom/coverage", json={
        "groups": [{"target": "DMZ", "expected": 5, "attempted": 5, "observed": 6}]},
        headers=AUTH)
    assert response.status_code == 422
    assert "target list is stale" in response.json()["detail"]


@pytest.mark.asyncio
async def test_a_probe_ledger_becomes_a_row_with_its_refusals(authenticated_client):
    response = await authenticated_client.post(
        "/api/v1/cbom/nbom/coverage/from-probes",
        json={"name": "External endpoints",
              "probes": [{"endpoint": "a:443", "status": "OK"},
                         {"endpoint": "b:443", "status": "TIMEOUT"},
                         {"endpoint": "c:443", "status": "MAYBE"}],
              "declared": ["a:443", "b:443", "d:443"]}, headers=AUTH)
    body = response.json()
    assert body["row"]["observed"] == 1
    assert body["row"]["failed"] == 1
    assert body["row"]["unattempted"] == 1
    assert body["row"]["declared_not_probed"] == ["d:443"]
    assert body["refused"][0]["status"] == "MAYBE"
    assert "never probed" in body["statement"]


@pytest.mark.asyncio
async def test_a_coverage_request_that_is_not_a_group_is_refused(authenticated_client):
    response = await authenticated_client.post("/api/v1/cbom/nbom/coverage",
                                               json={"groups": ["DMZ"]}, headers=AUTH)
    assert response.status_code == 422
