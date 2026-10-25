"""Owned PostgreSQL original-custody, standard export and metadata-join witness."""

import pytest
from test_assurance_workflows import assured as assured
from test_cbom_controlled_postgres import banks as banks, pytestmark as pytestmark
import test_linux_phase2_projections as contracts


@pytest.mark.parametrize(
    "contract",
    [
        contracts.test_linux_graph_and_official_sbom_reuse_originals_without_writes,
        contracts.test_failed_package_input_is_visible_even_in_valid_standard_export,
        contracts.test_uncompleted_job_cannot_export_or_create_relationships,
    ],
)
def test_postgres_linux_outputs(assured, contract):
    contract(assured)


def test_postgres_supported_runtime_joins(assured, monkeypatch):
    contracts.test_admitted_synthetic_runtime_facts_produce_only_supported_joins(assured, monkeypatch)
