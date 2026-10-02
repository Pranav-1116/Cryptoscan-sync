from datetime import datetime, timezone

from api.readiness.assurance import build_readiness_summary


def _snapshot(statuses):
    return {
        "ts": "2026-10-02T00:00:00+00:00",
        "results": {family: {"status": status} for family, status in statuses.items()},
        "scanner_availability": {},
    }


def test_missing_families_are_not_green():
    result = build_readiness_summary(
        _snapshot({"source": "PASS", "runtime": "PASS"}),
        dependency={"status": "PASS"},
        now=datetime(2026, 10, 2, 0, 5, tzinfo=timezone.utc),
    )
    assert result["controlled_staging"]["status"] == "BLOCKED"
    assert result["scanner"]["status_counts"]["UNAVAILABLE"] >= 1
    assert result["regulated_production"]["status"] == "BLOCKED"


def test_explicit_fail_and_preflight_survive_aggregation():
    result = build_readiness_summary(
        _snapshot({"source": "FAIL", "network": "PREFLIGHT", "runtime": "PASS"}),
        dependency={"status": "PASS"},
        now=datetime(2026, 10, 2, 0, 5, tzinfo=timezone.utc),
    )
    assert result["scanner"]["status_counts"]["FAIL"] == 1
    assert result["scanner"]["status_counts"]["PREFLIGHT"] == 1
    assert {row["family"] for row in result["scanner"]["gaps"]} >= {"source", "network"}


def test_fresh_mechanically_complete_snapshot_still_needs_external_evidence():
    statuses = {family: "PASS" for family in (
        "vendor", "universal", "source", "runtime", "hardware", "network",
        "cloud", "container", "ot", "telecom", "payment", "keyassure",
        "binary", "devsecops",
    )}
    result = build_readiness_summary(
        _snapshot(statuses),
        dependency={"status": "PASS", "unresolved_relationships": []},
        external={"categories": [{"category": "independent_review", "status": "SKIP"}]},
        now=datetime(2026, 10, 2, 0, 5, tzinfo=timezone.utc),
    )
    assert result["controlled_staging"]["status"] == "PASS"
    assert result["production_pilot"]["status"] == "SKIP"
    assert result["regulated_production"]["status"] == "BLOCKED"
    assert result["safety"]["customer_attestation_inferred"] is False
