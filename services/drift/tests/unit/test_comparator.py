"""
Unit tests for the Comparator — drift detection logic.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from drift.classifiers.drift_type_classifier import DriftTypeClassifier
from drift.classifiers.severity_calculator import SeverityCalculator
from drift.core.comparator import Comparator
from drift.fingerprinting.inventory_builder import CryptoInventory, InventoryBuilder
from drift.fingerprinting.fingerprinter import Fingerprint, Fingerprinter
from drift.models.drift_event import DriftType, DriftSeverity


def make_inventory(
    scan_id=None,
    records: list[dict] | None = None,
) -> CryptoInventory:
    """Helper to build inventory from records."""
    scan_id = scan_id or uuid4()
    records = records or []
    builder = InventoryBuilder()
    return builder.build(scan_id=scan_id, evidence_records=records)


def make_record(
    algorithm: str = "AES",
    mode: str = "GCM",
    file_path: str = "src/main/Crypto.java",
    line_number: int = 100,
    compliance_status: str = "PASS",
    is_hardcoded_key: bool = False,
) -> dict:
    return {
        "evidence_id": str(uuid4()),
        "algorithm": algorithm,
        "mode": mode,
        "file_path": file_path,
        "line_number": line_number,
        "class_name": "com.example.CryptoService",
        "method_name": "encryptData",
        "compliance_status": compliance_status,
        "is_hardcoded_key": is_hardcoded_key,
        "normalized_crypto": {
            "algorithm": algorithm,
            "mode": mode,
            "nist_designation": "APPROVED" if compliance_status == "PASS" else "DISALLOWED",
        },
    }


@pytest.fixture
def comparator() -> Comparator:
    return Comparator(
        type_classifier=DriftTypeClassifier(),
        severity_calculator=SeverityCalculator(),
    )


class TestComparatorNoDrift:
    """Tests for scenarios where no drift is expected."""

    def test_identical_inventories_no_drift(self, comparator: Comparator) -> None:
        record = make_record(algorithm="AES", mode="GCM", file_path="src/Crypto.java", line_number=10)
        baseline = make_inventory(records=[record])
        current = make_inventory(records=[record])

        result = comparator.compare(
            baseline=baseline,
            current=current,
            system_identifier="test-repo",
        )

        assert not result.has_drift
        assert len(result.drift_events) == 0

    def test_empty_both_inventories_no_drift(self, comparator: Comparator) -> None:
        baseline = make_inventory(records=[])
        current = make_inventory(records=[])

        result = comparator.compare(
            baseline=baseline,
            current=current,
            system_identifier="test-repo",
        )

        assert not result.has_drift

    def test_multiple_identical_findings(self, comparator: Comparator) -> None:
        records = [
            make_record(algorithm="AES", file_path="src/A.java", line_number=10),
            make_record(algorithm="RSA", file_path="src/B.java", line_number=20),
            make_record(algorithm="SHA-256", file_path="src/C.java", line_number=30),
        ]
        baseline = make_inventory(records=records)
        current = make_inventory(records=records)

        result = comparator.compare(
            baseline=baseline,
            current=current,
            system_identifier="payment-api",
        )

        assert not result.has_drift


class TestNewCryptoDrift:
    """Tests for NEW_CRYPTO drift detection."""

    def test_detects_new_des_as_critical(self, comparator: Comparator) -> None:
        baseline_record = make_record(algorithm="AES", file_path="src/Safe.java")
        new_record = make_record(
            algorithm="DES",
            file_path="src/Payment.java",
            line_number=247,
            compliance_status="FAIL",
        )

        baseline = make_inventory(records=[baseline_record])
        current = make_inventory(records=[baseline_record, new_record])

        result = comparator.compare(
            baseline=baseline,
            current=current,
            system_identifier="payment-api",
        )

        assert result.has_drift
        assert len(result.drift_events) == 1

        event = result.drift_events[0]
        assert event.drift_type == DriftType.NEW_CRYPTO
        assert event.severity == DriftSeverity.CRITICAL
        assert "DES" in event.algorithm

    def test_detects_new_compliant_crypto_as_medium(
        self, comparator: Comparator
    ) -> None:
        baseline_record = make_record(algorithm="AES", file_path="src/Old.java")
        new_record = make_record(
            algorithm="AES",
            mode="GCM",
            file_path="src/New.java",
            line_number=50,
            compliance_status="PASS",
        )

        baseline = make_inventory(records=[baseline_record])
        current = make_inventory(records=[baseline_record, new_record])

        result = comparator.compare(
            baseline=baseline,
            current=current,
            system_identifier="test-repo",
        )

        assert result.has_drift
        new_event = next(
            e for e in result.drift_events if e.drift_type == DriftType.NEW_CRYPTO
        )
        assert new_event.severity == DriftSeverity.MEDIUM

    def test_hardcoded_key_is_critical(self, comparator: Comparator) -> None:
        hardcoded_record = make_record(
            algorithm="AES",
            file_path="src/Bad.java",
            line_number=99,
            compliance_status="FAIL",
            is_hardcoded_key=True,
        )

        baseline = make_inventory(records=[])
        current = make_inventory(records=[hardcoded_record])

        result = comparator.compare(
            baseline=baseline,
            current=current,
            system_identifier="test-repo",
        )

        assert result.has_drift
        event = result.drift_events[0]
        assert event.severity == DriftSeverity.CRITICAL


class TestRemovedCryptoDrift:
    """Tests for REMOVED_CRYPTO drift detection."""

    def test_detects_removed_compliant_as_medium(
        self, comparator: Comparator
    ) -> None:
        record = make_record(
            algorithm="AES",
            file_path="src/Crypto.java",
            line_number=10,
            compliance_status="PASS",
        )

        baseline = make_inventory(records=[record])
        current = make_inventory(records=[])  # Record removed

        result = comparator.compare(
            baseline=baseline,
            current=current,
            system_identifier="test-repo",
        )

        assert result.has_drift
        event = result.drift_events[0]
        assert event.drift_type == DriftType.REMOVED_CRYPTO
        assert event.severity == DriftSeverity.MEDIUM

    def test_detects_removed_noncompliant_as_info(
        self, comparator: Comparator
    ) -> None:
        """Removing non-compliant crypto is informational (positive)."""
        record = make_record(
            algorithm="DES",
            file_path="src/OldCrypto.java",
            compliance_status="FAIL",
        )

        baseline = make_inventory(records=[record])
        current = make_inventory(records=[])

        result = comparator.compare(
            baseline=baseline,
            current=current,
            system_identifier="test-repo",
        )

        assert result.has_drift
        event = result.drift_events[0]
        assert event.drift_type == DriftType.REMOVED_CRYPTO
        assert event.severity == DriftSeverity.INFO


class TestDriftSummary:
    """Tests for DriftSummary aggregation."""

    def test_summary_counts_correct(self, comparator: Comparator) -> None:
        baseline = make_inventory(records=[])
        new_records = [
            make_record(
                algorithm="DES", file_path=f"src/File{i}.java",
                line_number=i, compliance_status="FAIL"
            )
            for i in range(3)
        ]
        current = make_inventory(records=new_records)

        result = comparator.compare(
            baseline=baseline,
            current=current,
            system_identifier="test-repo",
        )

        summary = result.summary
        assert summary.critical == 3
        assert summary.total_drift_events == 3
        assert summary.new_crypto_count == 3
        assert summary.has_critical
        assert summary.has_actionable_drift
        assert summary.highest_severity == "CRITICAL"

    def test_summary_no_drift(self, comparator: Comparator) -> None:
        record = make_record()
        inventory = make_inventory(records=[record])

        result = comparator.compare(
            baseline=inventory,
            current=inventory,
            system_identifier="test-repo",
        )

        summary = result.summary
        assert summary.total_drift_events == 0
        assert not summary.has_critical
        assert not summary.has_actionable_drift
        assert summary.highest_severity == "NONE"