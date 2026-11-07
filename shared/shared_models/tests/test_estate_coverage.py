"""Estate Coverage Intelligence — roadmap item 6 acceptance rows.

Standing directive: "A missing asset must never silently become a clean security
result." Also: failed reads never print zeros, and a percentage over an unknown
denominator is refused.
"""

from __future__ import annotations

from shared_models.estate_coverage import (
    COVERAGE_SCHEMA,
    VERDICT_ATTENTION,
    VERDICT_COMPLETE,
    VERDICT_INCOMPLETE,
    coverage_intelligence,
)


def ok(plane="endpoint.inventory", expected=4, collected=4):
    return {"plane": plane, "status": "COMPLETE", "expected": expected,
            "collected": collected, "reason": None, "impact": None,
            "is_failure": False}


def failed(plane="runtime.discovery", expected=0, collected=0):
    return {"plane": plane, "status": "FAILED", "expected": expected,
            "collected": collected, "reason": "crashed",
            "impact": "this plane's inventory is UNKNOWN — the BOMs that depend "
                      "on it are incomplete, and no statement about missing "
                      "crypto in this plane is valid",
            "is_failure": True}


class TestVerdictLadder:

    def test_a_fully_collected_run_is_complete(self):
        record = coverage_intelligence(
            authorized_targets=4, discovered_assets=4,
            collector_outcomes=[ok()])
        assert record["schema"] == COVERAGE_SCHEMA
        assert record["verdict"] == VERDICT_COMPLETE
        assert record["coverage_percent"] == 100.0

    def test_an_unknown_asset_is_never_a_clean_result(self):
        record = coverage_intelligence(
            authorized_targets=10, discovered_assets=9,
            collector_outcomes=[ok(expected=10, collected=10)],
            unknown_assets=1)
        assert record["verdict"] == VERDICT_INCOMPLETE
        gap = next(g for g in record["gaps"] if g["kind"] == "UNKNOWN_ASSET")
        assert gap["is_clean_result"] is False
        assert "never silently become a clean security result" in gap["detail"]

    def test_an_undiscovered_authorized_target_is_a_gap_not_a_pass(self):
        record = coverage_intelligence(
            authorized_targets=10, discovered_assets=7,
            collector_outcomes=[ok(expected=7, collected=7)])
        gap = next(g for g in record["gaps"] if g["kind"] == "UNDISCOVERED_TARGET")
        assert gap["count"] == 3
        assert record["verdict"] == VERDICT_INCOMPLETE

    def test_an_access_denied_target_is_never_an_empty_risk_result(self):
        record = coverage_intelligence(
            authorized_targets=4, discovered_assets=4,
            collector_outcomes=[ok()], access_denied_targets=2)
        gap = next(g for g in record["gaps"] if g["kind"] == "ACCESS_DENIED")
        assert "never an empty-risk result" in gap["detail"]
        assert record["verdict"] == VERDICT_INCOMPLETE

    def test_stale_evidence_demands_attention_without_a_collection_gap(self):
        record = coverage_intelligence(
            authorized_targets=4, discovered_assets=4,
            collector_outcomes=[ok()], stale_evidence=6)
        assert record["verdict"] == VERDICT_ATTENTION
        assert record["stale_evidence"] == 6
        assert any(i["kind"] == "STALE_EVIDENCE" for i in record["attention_items"])

    def test_unverified_relationships_and_unsupported_types_are_reported(self):
        record = coverage_intelligence(
            authorized_targets=4, discovered_assets=4,
            collector_outcomes=[ok()],
            unverified_relationships=3,
            unsupported_types=["legacy-tape-drive", "legacy-tape-drive"])
        assert record["verdict"] == VERDICT_ATTENTION
        assert record["unsupported_types"] == ["legacy-tape-drive"]
        kinds = {i["kind"] for i in record["attention_items"]}
        assert "UNVERIFIED_RELATIONSHIP" in kinds
        assert "UNSUPPORTED_TYPE" in kinds


class TestFailedReadsNeverPrintZeros:

    def test_a_failed_collector_marks_its_plane_unobserved_not_empty(self):
        record = coverage_intelligence(
            authorized_targets=4, discovered_assets=4,
            collector_outcomes=[ok(), failed()])
        assert record["verdict"] == VERDICT_INCOMPLETE
        plane = next(r for r in record["collectors"] if r["plane"] == "runtime.discovery")
        assert plane["status"] == "FAILED"
        assert plane["is_failure"] is True
        assert "UNKNOWN" in plane["impact"]  # impact text survives
        gap = next(g for g in record["gaps"] if g["kind"] == "COLLECTOR_FAILED")
        assert "never empty and never clean" in gap["detail"]

    def test_a_percentage_over_an_unknown_denominator_is_refused(self):
        record = coverage_intelligence(
            authorized_targets=4, discovered_assets=4,
            collector_outcomes=[ok(), failed()])  # failed row: expected 0
        assert record["coverage_percent"] is None
        assert "refused, not estimated" in record["percent_note"]

    def test_a_known_denominator_still_gets_its_honest_percentage(self):
        record = coverage_intelligence(
            authorized_targets=10, discovered_assets=10,
            collector_outcomes=[ok(expected=10, collected=6)])
        # partial: 6 of 10 — and a PARTIAL row is a gap, but the denominator is known
        assert record["coverage_percent"] == 60.0
        assert record["verdict"] == VERDICT_INCOMPLETE

    def test_a_partial_collector_counts_the_remainder_as_unobserved(self):
        record = coverage_intelligence(
            authorized_targets=10, discovered_assets=10,
            collector_outcomes=[ok(expected=10, collected=6)])
        gap = next(g for g in record["gaps"] if g["kind"] == "PARTIAL_OBSERVATION")
        assert gap["count"] == 4
        assert "NOT_OBSERVED, not absent" in gap["detail"]

    def test_collectors_needing_attention_lists_failures_and_partials(self):
        record = coverage_intelligence(
            authorized_targets=10, discovered_assets=10,
            collector_outcomes=[ok(), ok(plane="a", expected=2, collected=1),
                                failed()])
        attention = {row["plane"] for row in record["collectors_needing_attention"]}
        assert attention == {"a", "runtime.discovery"}

    def test_every_item6_dimension_is_present_in_the_record(self):
        record = coverage_intelligence(
            authorized_targets=1, discovered_assets=1, collector_outcomes=[ok()])
        for key in ("authorized_targets", "discovered_assets", "collectors",
                    "collectors_needing_attention", "unknown_assets",
                    "stale_evidence", "unsupported_types", "access_denied_targets",
                    "unverified_relationships", "freshness", "gaps",
                    "attention_items", "coverage_percent"):
            assert key in record, key
