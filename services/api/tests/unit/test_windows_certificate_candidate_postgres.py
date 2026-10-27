"""Owned PostgreSQL; Windows native API results are explicitly portable fixtures."""

import pytest
from test_assurance_workflows import assured as assured
from test_cbom_controlled_postgres import banks as banks, pytestmark as pytestmark
import test_windows_certificate_candidate as contracts


def test_postgres_certificate_custody_and_standard_cbom(assured, monkeypatch):
    contracts.test_scoped_windows_certificate_import_and_existing_standard_cbom(assured, monkeypatch)


@pytest.mark.parametrize("mode,status", [("denied", "DENIED"), ("missing", "UNAVAILABLE"), ("elevated", "DENIED")])
def test_postgres_certificate_failure_outcome(assured, monkeypatch, mode, status):
    contracts.test_failed_certificate_receipt_never_becomes_no_certificate_or_positive_cbom(
        assured, monkeypatch, mode, status
    )


def test_postgres_certificate_scope_mismatch(assured, monkeypatch):
    contracts.test_store_fingerprint_scope_mismatch_refuses_intake_before_persistence(assured, monkeypatch)


def test_postgres_windows_candidate_admission_stays_blocked(assured):
    contracts.test_windows_registry_jobs_stay_blocked_and_no_remote_admission_is_added(assured)
