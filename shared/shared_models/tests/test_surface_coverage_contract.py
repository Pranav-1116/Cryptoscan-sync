"""Public coverage schema invariants, not host/native qualification."""

from copy import deepcopy
import pytest
from pydantic import ValidationError
from shared_models.collection_coverage import CoverageReport, SURFACES, BOMS


def packet():
    return {
        "job_id": "synthetic-job",
        "target_id": "synthetic-target",
        "target_revision": 2,
        "target_sha256": "a" * 64,
        "system_id": "synthetic-system",
        "environment": "UAT",
        "started_at": "2026-10-25T01:00:00+00:00",
        "finished_at": "2026-10-25T01:00:01+00:00",
        "envelope_sha256": "b" * 64,
        "surfaces": {
            k: {
                "approved_inputs": 0,
                "parsed_inputs": 0,
                "failed_inputs": 0,
                "fact_count": 0,
                "outcome": "NOT_REQUESTED",
                "approved_input_parse_percent": None,
                "inputs": [],
            }
            for k in SURFACES
        },
        "bom_observation_counts": {k: 0 for k in BOMS},
    }


def test_strict_report_never_promotes_unknown_coverage():
    value = CoverageReport.model_validate(packet())
    assert value.whole_host_percent is None and not value.asset_absence_proven
    assert value.materialized_without_collection and not value.production_execution_qualified


@pytest.mark.parametrize(
    "change",
    [
        "absence",
        "whole-percent",
        "production",
        "wrong-bom",
        "missing-surface",
        "invented-facts",
        "negative-count",
        "naive-time",
        "reverse-time",
        "extra-field",
        "wrong-denominator",
        "not-requested-percent",
    ],
)
def test_report_rejects_promoted_or_inconsistent_counts(change):
    value = deepcopy(packet())
    if change == "absence":
        value["asset_absence_proven"] = True
    elif change == "whole-percent":
        value["whole_host_percent"] = 100
    elif change == "production":
        value["production_execution_qualified"] = True
    elif change == "wrong-bom":
        value["bom_observation_counts"]["FAKE"] = 0
    elif change == "missing-surface":
        value["surfaces"].pop("software")
    elif change == "invented-facts":
        value["bom_observation_counts"]["SBOM"] = 1
    elif change == "negative-count":
        value["bom_observation_counts"]["SBOM"] = -1
    elif change == "naive-time":
        value["started_at"] = "2026-10-25T01:00:00"
    elif change == "reverse-time":
        value["finished_at"] = "2026-10-25T00:00:00+00:00"
    elif change == "extra-field":
        value["automatic_scan"] = True
    elif change == "wrong-denominator":
        value["surfaces"]["software"]["approved_inputs"] = 10
    else:
        value["surfaces"]["software"]["approved_input_parse_percent"] = 0.0
    with pytest.raises(ValidationError):
        CoverageReport.model_validate(value)


def test_parsed_no_facts_is_not_an_absence_claim():
    value = packet()
    value["surfaces"]["software"] = {
        "approved_inputs": 1,
        "parsed_inputs": 1,
        "failed_inputs": 0,
        "fact_count": 0,
        "outcome": "PARSED_NO_FACTS",
        "approved_input_parse_percent": 100.0,
        "inputs": [
            {
                "input_id": "empty",
                "kind": "DPKG_STATUS",
                "status": "PARSED",
                "reason": "PARSED_RECEIPT_NOT_ABSENCE_PROOF",
                "fact_count": 0,
                "evidence_ids": [],
                "local_basis_counts": {"OBSERVED": 0, "DECLARED": 0},
            }
        ],
    }
    result = CoverageReport.model_validate(value)
    assert result.surfaces["software"].outcome == "PARSED_NO_FACTS"
    assert not result.surfaces["software"].inputs[0].asset_absence_proven
