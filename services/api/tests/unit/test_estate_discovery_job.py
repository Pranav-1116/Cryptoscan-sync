"""One estate-discovery job, six BOM projections (spec 93 §15, §18).

The properties that matter here are the ones that make a *fan-out* honest:

* a collector that raises becomes ``FAILED`` with an impact statement — never an
  empty plane, never "no crypto";
* a plane with zero rows is reported as such (an empty store is not proof of an
  empty estate) and never as a clean result;
* coverage is attempted/expected, so a partial read is ``PARTIAL`` with a reason;
* the six BOMs still share one ``projection_id`` even when a plane failed, so a
  reader can tell "incomplete snapshot" from "six disagreeing snapshots";
* the lifecycle reports which phases actually ran.
"""

from __future__ import annotations

import pytest

from api import estate_discovery
from shared_models.estate_graph import BOM_KINDS

import test_network_protocol_safety as shared_api

api_fixture = pytest.fixture(name="api")(shared_api.client.__wrapped__)


def _network_plane(*, expected: int = 2, **overrides) -> dict:
    plane = {
        "plane": "NETWORK",
        "expected": expected,
        "collected": 2,
        "assets": [
            {"ref": "network:10.0.0.5:443", "type": "NETWORK_ENDPOINT", "name": "10.0.0.5:443",
             "identity": {"endpoint": "10.0.0.5:443"}},
            {"ref": "network:10.0.0.9:22", "type": "NETWORK_ENDPOINT", "name": "10.0.0.9:22",
             "identity": {"endpoint": "10.0.0.9:22"}},
        ],
        "evidence": [
            {"source": "network_scanner", "evidence_type": "NETWORK_ACTIVE_OBSERVED",
             "target": "network:10.0.0.5:443", "layer": "NETWORK_TRANSPORT",
             "evidence_id": "net-ev-1",
             "facts": {"tls_version": "TLSv1.2", "cipher_suite": "ECDHE-RSA-AES256-GCM-SHA384",
                       "protocol": "TLS"}},
            {"source": "network_scanner", "evidence_type": "UNKNOWN",
             "target": "network:10.0.0.9:22", "layer": "NETWORK_TRANSPORT",
             "evidence_id": "net-ev-2", "facts": {"protocol": "SSH"}},
        ],
    }
    plane.update(overrides)
    return plane


def _static_plane() -> dict:
    return {
        "plane": "STATIC",
        "expected": 1,
        "collected": 1,
        "assets": [{"ref": "static:ca-1", "type": "APPLICATION", "name": "payments-api",
                    "identity": {"application": "payments-api"}}],
        "evidence": [{"source": "static_scanner", "evidence_type": "STATIC_OBSERVED",
                      "target": "static:ca-1", "layer": "APPLICATION", "evidence_id": "static-ev-1",
                      "facts": {"algorithm": "RSA", "key_size": 2048}}],
    }


def _collectors(**planes) -> dict:
    return {name: (lambda _db, _payload=payload, **_kw: _payload) for name, payload in planes.items()}


def test_plan_covers_every_plane_and_names_what_each_cannot_see():
    plan = estate_discovery.plan()
    assert plan["enabled"] == list(estate_discovery.PLANES)
    assert plan["skipped"] == []
    for row in plan["planes"]:
        assert row["source"]
        assert row["boms"]
        assert row["limitation"], "a plane without a stated blind spot would over-claim"


def test_plan_marks_a_skipped_plane_not_attempted_with_impact():
    plan = estate_discovery.plan(planes=["NETWORK"])
    skipped = {row["plane"]: row for row in plan["planes"] if not row["enabled"]}
    assert set(skipped) == set(estate_discovery.PLANES) - {"NETWORK"}
    assert skipped["RUNTIME"]["status"] == "NOT_ATTEMPTED"
    assert "NOT_OBSERVED" in skipped["RUNTIME"]["impact"]


def test_unknown_plane_is_refused_rather_than_ignored():
    with pytest.raises(ValueError, match="unknown plane"):
        estate_discovery.plan(planes=["MAINFRAME"])


def test_job_merges_planes_into_one_graph_and_projects_six_boms():
    report = estate_discovery.run(
        object(), persist=False,
        collectors=_collectors(NETWORK=_network_plane(), STATIC=_static_plane()))
    assert report["model"] == "cryptoscan.estate-discovery-job/1"
    assert report["summary"]["assets"] == 3
    # planes with no adapter are coverage debt, not a pass
    assert report["verdict"] == "PARTIAL_COVERAGE"
    assert report["skipped_planes"] == []
    assert set(report["not_attempted_planes"]) == set(estate_discovery.PLANES) - {"NETWORK", "STATIC"}
    assert set(report["boms"]) == set(BOM_KINDS)
    assert {item["projection_id"] for item in report["boms"].values()} == {report["projection_id"]}
    assert report["consistency"] is not None
    # only the two requested planes ran; the rest are honest gaps
    skipped = [item for item in report["collectors"] if item["status"] == "NOT_ATTEMPTED"]
    assert {item["plane"] for item in skipped} == set(estate_discovery.PLANES) - {"NETWORK", "STATIC"}


def test_a_failing_collector_is_failed_with_impact_not_an_empty_plane():
    def boom(_db, **_kwargs):
        raise RuntimeError("HSM API unreachable")

    report = estate_discovery.run(
        object(), persist=False,
        collectors={"NETWORK": lambda _db, **_k: _network_plane(), "HARDWARE": boom})
    hardware = next(item for item in report["collectors"] if item["plane"] == "HARDWARE")
    assert hardware["status"] == "FAILED"
    assert "RuntimeError: HSM API unreachable" in hardware["reason"]
    assert "UNKNOWN" in hardware["impact"]
    assert "HBOM" in hardware["impact"], "the impact must name the BOM that loses coverage"
    assert "HARDWARE" in report["failed_planes"]
    assert report["verdict"] == "PARTIAL_COVERAGE"

    coverage = {row["target"]: row for row in report["coverage"]["targets"]}
    assert coverage["HARDWARE"]["status"] == "FAILED"
    assert "NOT_OBSERVED" not in coverage["HARDWARE"]["reason"] or coverage["HARDWARE"]["impact"]
    # the good plane is still projected: a failed plane must not void the snapshot
    assert set(report["boms"]) == set(BOM_KINDS)
    assert report["boms"]["NBOM"]["projection_id"] == report["projection_id"]


def test_an_empty_plane_says_empty_store_not_no_crypto():
    empty = {"plane": "RUNTIME", "expected": 0, "collected": 0, "assets": [], "evidence": [],
             "note": "no runtime crypto event is stored (NOT_OBSERVED, not 'no crypto')"}
    report = estate_discovery.run(object(), persist=False, collectors={"RUNTIME": lambda _db, **_k: empty})
    runtime = next(item for item in report["collectors"] if item["plane"] == "RUNTIME")
    assert runtime["status"] == "COMPLETE"
    assert "not 'no crypto'" in runtime["reason"]
    coverage = {row["target"]: row for row in report["coverage"]["targets"]}
    assert coverage["RUNTIME"]["expected"] == 0
    assert coverage["RUNTIME"]["status"] == "COMPLETE"


def test_partial_read_is_partial_with_a_reason_and_impact():
    partial = _network_plane(expected=10, collected=2, note="read 2 of 10 observation runs")
    report = estate_discovery.run(object(), persist=False, collectors={"NETWORK": lambda _db, **_k: partial})
    network = next(item for item in report["collectors"] if item["plane"] == "NETWORK")
    assert network["status"] == "PARTIAL"
    assert network["expected"] == 10 and network["collected"] == 2
    assert "read 2 of 10" in network["reason"]
    assert "NOT_OBSERVED" in network["impact"]
    assert report["partial_planes"] == ["NETWORK"]
    assert report["coverage"]["summary"]["coverage_percent"] == 20.0


def test_coverage_never_reads_as_percent_of_crypto_discovered():
    report = estate_discovery.run(
        object(), persist=False,
        collectors=_collectors(NETWORK=_network_plane(), STATIC=_static_plane()))
    coverage = report["coverage"]
    assert "attempted" in coverage["meaning"]
    assert "NOT 'percent of crypto discovered'" in coverage["meaning"]
    assert report["meaning"].count("never 'percent of crypto discovered'") == 1


def test_identity_is_resolved_across_planes():
    network = _network_plane()
    # the static plane describes the same application that the runtime endpoint fronts
    runtime = {"plane": "RUNTIME", "expected": 1, "collected": 1,
               "assets": [{"ref": "runtime:payments-api", "type": "APPLICATION",
                           "name": "payments-api", "identity": {"application": "payments-api"}}],
               "evidence": [{"source": "runtime_agent", "evidence_type": "RUNTIME_OBSERVED",
                             "target": "runtime:payments-api", "layer": "APPLICATION",
                             "evidence_id": "rt-ev-1",
                             "facts": {"algorithm": "AES", "operation": "ENCRYPT"}}]}
    report = estate_discovery.run(
        object(), persist=False,
        collectors=_collectors(NETWORK=network, STATIC=_static_plane(), RUNTIME=runtime))
    # STATIC and RUNTIME both describe payments-api with the same identity key
    assert report["summary"]["assets"] == 3
    assert report["merged_identities"], "co-located evidence on one identity must merge, not duplicate"
    cbom = report["boms"]["CBOM"]
    assert cbom["components"], "a merged identity still has to reach the CBOM"


def test_lifecycle_reports_the_phases_that_ran():
    report = estate_discovery.run(
        object(), persist=False,
        collectors=_collectors(NETWORK=_network_plane()))
    phases = [item["phase"] for item in report["lifecycle"]]
    for expected in ("SCOPE_RESOLVED", "COLLECTORS_PLANNED", "EVIDENCE_COLLECTED", "NORMALIZED",
                     "IDENTITY_RESOLVED", "CORRELATED", "EVIDENCE_VALIDATED", "COVERAGE_ASSESSED",
                     "BOMS_PROJECTED"):
        assert expected in phases, expected
    assert phases.index("COVERAGE_ASSESSED") < phases.index("BOMS_PROJECTED")


def test_boms_can_be_skipped_without_pretending_they_were_projected():
    report = estate_discovery.run(
        object(), persist=False, include_boms=False,
        collectors=_collectors(NETWORK=_network_plane()))
    assert "boms" not in report
    assert "BOMS_PROJECTED" not in [item["phase"] for item in report["lifecycle"]]


def test_every_default_plane_has_an_adapter():
    assert set(estate_discovery.DEFAULT_COLLECTORS) == set(estate_discovery.PLANES)
    for plane, collector in estate_discovery.DEFAULT_COLLECTORS.items():
        assert callable(collector), plane


def test_api_plan_lists_the_planes(api):
    http, _session = api
    response = http.get("/api/v1/estate/evidence/plan")
    assert response.status_code == 200
    body = response.json()
    assert body["model"] == "cryptoscan.estate-collector-plan/1"
    assert {row["plane"] for row in body["planes"]} == set(estate_discovery.PLANES)


def test_api_scan_runs_one_job_and_reports_honest_coverage(api):
    http, _session = api
    response = http.post("/api/v1/estate/evidence/scan",
                         json={"estate": "api-estate", "persist": False, "include_boms": True})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["model"] == "cryptoscan.estate-discovery-job/1"
    assert "FAILED" not in {row["status"] for row in body["coverage"]["targets"]}
    assert set(body["boms"]) == set(BOM_KINDS)
    # an empty database is an empty store, never a verdict about crypto
    assert "no crypto" not in body["meaning"].lower().replace("never 'no crypto found'", "")
    assert body["verdict"] in {"COMPLETE", "PARTIAL_COVERAGE"}
    assert "NOT_OBSERVED" in " ".join(body["limitations"])


def test_api_scan_rejects_an_unknown_plane(api):
    http, _session = api
    response = http.post("/api/v1/estate/evidence/scan", json={"planes": ["MAINFRAME"], "persist": False})
    assert response.status_code == 422
    assert response.json()["detail"]["error"] == "estate_scan_rejected"
