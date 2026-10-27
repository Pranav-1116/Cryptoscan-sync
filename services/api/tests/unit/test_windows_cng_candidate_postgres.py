"""Owned PostgreSQL with explicit portable CNG fixtures, not native qualification."""

import pytest
from test_assurance_workflows import assured as assured
from test_cbom_controlled_postgres import banks as banks, pytestmark as pytestmark
import test_windows_cng_candidate as contracts


def test_postgres_registration_custody(assured, monkeypatch):
    contracts.test_registration_custody_does_not_emit_algorithm_use_or_recollect(assured, monkeypatch)


@pytest.mark.parametrize(
    "mode,status", [("denied", "DENIED"), ("missing", "UNAVAILABLE"), ("changed", "INVALID"), ("elevated", "DENIED")]
)
def test_postgres_registration_failures(assured, monkeypatch, mode, status):
    contracts.test_failed_registration_is_unknown_not_no_crypto_or_supported_crypto(assured, monkeypatch, mode, status)


@pytest.mark.parametrize("change", ["interface", "digest", "functions", "capability"])
def test_postgres_registration_scope(assured, monkeypatch, change):
    contracts.test_changed_registration_scope_truth_or_commitment_refuses_before_persistence(
        assured, monkeypatch, change
    )


def test_postgres_registration_admission(assured):
    contracts.test_registration_candidate_does_not_enable_windows_worker_admission(assured)
