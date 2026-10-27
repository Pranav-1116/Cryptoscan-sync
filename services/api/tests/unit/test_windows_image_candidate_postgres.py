"""Owned PostgreSQL with portable Windows-native seams; no native qualification."""

import pytest
from test_assurance_workflows import assured as assured
from test_cbom_controlled_postgres import banks as banks, pytestmark as pytestmark
import test_windows_image_candidate as contracts


def test_postgres_image_custody(assured, monkeypatch):
    contracts.test_scoped_image_custody_does_not_create_crypto_components_or_recollect(assured, monkeypatch)


@pytest.mark.parametrize(
    "mode,status", [("denied", "DENIED"), ("missing", "UNAVAILABLE"), ("changed", "INVALID"), ("elevated", "DENIED")]
)
def test_postgres_image_failures(assured, monkeypatch, mode, status):
    contracts.test_image_failure_is_not_absence_or_crypto_inventory(assured, monkeypatch, mode, status)


@pytest.mark.parametrize(
    "field,value",
    [
        ("pid", 72),
        ("creation_filetime", contracts.CREATED[:-1] + "2"),
        ("creation_filetime", int(contracts.CREATED)),
        ("interface_sha256", "0" * 64),
        ("runtime_use", "OBSERVED"),
    ],
)
def test_postgres_image_scope(assured, monkeypatch, field, value):
    contracts.test_changed_scope_or_truth_refuses_intake_before_persistence(assured, monkeypatch, field, value)


def test_postgres_image_admission_stays_blocked(assured):
    contracts.test_module_candidate_does_not_enable_windows_worker_admission(assured)
