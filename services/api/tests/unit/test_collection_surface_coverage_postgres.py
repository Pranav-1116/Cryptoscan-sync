"""Owned PostgreSQL: coverage reads the same committed evidence without writes."""

import pytest
from test_assurance_workflows import assured as assured
from test_cbom_controlled_postgres import banks as banks, pytestmark as pytestmark
import test_collection_surface_coverage as contracts


@pytest.mark.parametrize(
    "contract",
    [
        contracts.test_phase_one_surface_coverage_same_evidence_and_all_six_boms,
        contracts.test_not_completed_and_changed_original_cannot_be_reported_as_covered,
        contracts.test_tampered_original_refuses_coverage_and_revoke_does_not_recollect,
    ],
)
def test_postgres_coverage(assured, contract):
    contract(assured)
