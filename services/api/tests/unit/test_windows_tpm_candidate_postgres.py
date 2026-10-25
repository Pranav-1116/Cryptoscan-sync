"""Owned PostgreSQL; TBS results are portable seams, never native evidence."""

import pytest
from test_assurance_workflows import assured as assured
from test_cbom_controlled_postgres import banks as banks, pytestmark as pytestmark
import test_windows_tpm_candidate as contracts


def test_postgres_tpm_custody(assured, monkeypatch):
    contracts.test_tpm_custody_no_crypto_component_or_recollection(assured, monkeypatch)


@pytest.mark.parametrize(
    "mode,status",
    [("missing", "UNAVAILABLE"), ("service", "UNAVAILABLE"), ("layout", "UNSUPPORTED"), ("elevated", "DENIED")],
)
def test_postgres_tpm_failure(assured, monkeypatch, mode, status):
    contracts.test_tpm_failure_not_hardware_absence_or_no_crypto(assured, monkeypatch, mode, status)


@pytest.mark.parametrize(
    "field,value", [("tpm_specification", "1.2"), ("interface_sha256", "0" * 64), ("capabilities_observed", True)]
)
def test_postgres_tpm_commitment(assured, monkeypatch, field, value):
    contracts.test_tpm_changed_commitment_or_promoted_claim_refuses_before_persistence(
        assured, monkeypatch, field, value
    )


def test_postgres_tpm_admission(assured):
    contracts.test_tpm_candidate_does_not_enable_windows_admission(assured)
