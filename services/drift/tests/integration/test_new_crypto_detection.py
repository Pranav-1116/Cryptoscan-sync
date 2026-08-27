"""
Integration test: Full drift detection when new non-compliant crypto is added.

Tests the complete flow: inventory building → comparison → event creation.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from drift.alerts.alert_dispatcher import AlertDispatcher
from drift.alerts.email_alerter import EmailAlerter
from drift.classifiers.drift_type_classifier import DriftTypeClassifier
from drift.classifiers.severity_calculator import SeverityCalculator
from drift.core.comparator import Comparator
from drift.core.detector import BaselineInfo, DriftDetector
from drift.fingerprinting.fingerprinter import Fingerprinter
from drift.fingerprinting.inventory_builder import InventoryBuilder
from drift.models.drift_event import DriftSeverity, DriftType

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock


def make_evidence_record(
    algorithm: str,
    file_path: str,
    line_number: int,
    compliance_status: str = "PASS",
    is_hardcoded_key: bool = False,
    mode: str | None = None,
    key_size: int | None = None,
) -> dict:
    return {
        "evidence_id": str(uuid4()),
        "scan_id": str(uuid4()),
        "algorithm": algorithm,
        "mode": mode,
        "key_size": key_size,
        "file_path": file_path,
        "line_number": line_number,
        "class_name": "com.example.TestClass",
        "method_name": "testMethod",
        "compliance_status": compliance_status,
        "is_hardcoded_key": is_hardcoded_key,
        "normalized_crypto": {
            "algorithm": algorithm,
            "mode": mode,
            "nist_designation": "APPROVED" if compliance_status == "PASS" else "DISALLOWED",
        },
    }


@pytest.fixture
def baseline_scan_id():
    return uuid4()


@pytest.fixture
def current_scan_id():
    return uuid4()


@pytest.fixture
def baseline_id():
    return uuid4()


@pytest.fixture
def baseline_info(baseline_scan_id, baseline_id) -> BaselineInfo:
    return BaselineInfo(
        baseline_id=baseline_id,
        approved_scan_id=baseline_scan_id,
        approved_by="alice.security",
        approved_at=datetime.now(timezone.utc),
        system_identifier="https://github.com/org/payment-api",
        environment="prod",
    )


@pytest.fixture
def mock_email_alerter():
    alerter = MagicMock(spec=EmailAlerter)
    alerter.send = AsyncMock()
    return alerter


@pytest.fixture
def drift_detector(mock_email_alerter) -> DriftDetector:
    return DriftDetector(
        inventory_builder=InventoryBuilder(Fingerprinter()),
        comparator=Comparator(
            type_classifier=DriftTypeClassifier(),
            severity_calculator=SeverityCalculator(),
        ),
        alert_dispatcher=AlertDispatcher(
            email_alerter=mock_email_alerter,
            max_retries=1,
        ),
    )


class TestNewCryptoDriftDetection:
    """Integration tests for adding new non-compliant crypto."""

    @pytest.mark.asyncio
    async def test_new_des_detected_as_critical(
        self,
        drift_detector: DriftDetector,
        baseline_info: BaselineInfo,
        current_scan_id: uuid4,
        mock_email_alerter,
    ) -> None:
        """Adding DES to a codebase should create CRITICAL drift event."""
        # Baseline: only AES (compliant)
        baseline_records = [
            make_evidence_record(
                algorithm="AES",
                file_path="src/main/SafeEncryption.java",
                line_number=50,
                compliance_status="PASS",
                mode="GCM",
            )
        ]

        # Current: AES + new DES (non-compliant)
        current_records = [
            make_evidence_record(
                algorithm="AES",
                file_path="src/main/SafeEncryption.java",
                line_number=50,
                compliance_status="PASS",
                mode="GCM",
            ),
            make_evidence_record(
                algorithm="DES",
                file_path="src/main/Payment.java",
                line_number=247,
                compliance_status="FAIL",
            ),
        ]

        result = await drift_detector.detect(
            current_scan_id=current_scan_id,
            system_identifier=baseline_info.system_identifier,
            baseline_info=baseline_info,
            baseline_evidence_records=baseline_records,
            current_evidence_records=current_records,
            notification_emails=["security@example.com"],
        )

        assert result.success
        assert result.drift_detected

        drift_events = result.comparison_result.drift_events
        new_events = [e for e in drift_events if e.drift_type == DriftType.NEW_CRYPTO]

        assert len(new_events) == 1
        des_event = new_events[0]
        assert des_event.severity == DriftSeverity.CRITICAL
        assert "DES" in des_event.algorithm
        assert "Payment.java" in des_event.location

        # Verify email was sent
        mock_email_alerter.send.assert_called_once()

        # Verify drift summary
        summary = result.drift_summary
        assert summary.critical == 1
        assert summary.total_drift_events == 1
        assert summary.has_critical

    @pytest.mark.asyncio
    async def test_first_scan_no_baseline_skips_detection(
        self,
        drift_detector: DriftDetector,
        current_scan_id,
    ) -> None:
        """First scan of a system should skip drift detection."""
        records = [
            make_evidence_record(
                algorithm="AES",
                file_path="src/main/Crypto.java",
                line_number=10,
            )
        ]

        result = await drift_detector.detect(
            current_scan_id=current_scan_id,
            system_identifier="https://github.com/org/new-repo",
            baseline_info=None,  # No baseline
            baseline_evidence_records=[],
            current_evidence_records=records,
            notification_emails=["security@example.com"],
        )

        assert result.success
        assert not result.drift_detected
        assert result.no_baseline_exists
        assert result.comparison_result is None

    @pytest.mark.asyncio
    async def test_no_drift_no_email_sent(
        self,
        drift_detector: DriftDetector,
        baseline_info: BaselineInfo,
        current_scan_id,
        mock_email_alerter,
    ) -> None:
        """When no drift detected, email should NOT be sent."""
        records = [
            make_evidence_record(
                algorithm="AES",
                file_path="src/main/Crypto.java",
                line_number=50,
                compliance_status="PASS",
            )
        ]

        result = await drift_detector.detect(
            current_scan_id=current_scan_id,
            system_identifier=baseline_info.system_identifier,
            baseline_info=baseline_info,
            baseline_evidence_records=records,
            current_evidence_records=records,
            notification_emails=["security@example.com"],
        )

        assert result.success
        assert not result.drift_detected

        # No email sent for no drift
        mock_email_alerter.send.assert_not_called()

    @pytest.mark.asyncio
    async def test_hardcoded_key_triggers_critical_alert(
        self,
        drift_detector: DriftDetector,
        baseline_info: BaselineInfo,
        current_scan_id,
        mock_email_alerter,
    ) -> None:
        """Hardcoded key should always be CRITICAL drift."""
        baseline_records = []  # Empty baseline

        current_records = [
            make_evidence_record(
                algorithm="AES",
                file_path="src/main/HardcodedKey.java",
                line_number=33,
                compliance_status="FAIL",
                is_hardcoded_key=True,
            )
        ]

        result = await drift_detector.detect(
            current_scan_id=current_scan_id,
            system_identifier=baseline_info.system_identifier,
            baseline_info=baseline_info,
            baseline_evidence_records=baseline_records,
            current_evidence_records=current_records,
            notification_emails=["security@example.com"],
        )

        assert result.success
        assert result.drift_detected

        event = result.comparison_result.drift_events[0]
        assert event.severity == DriftSeverity.CRITICAL

        # Email should be sent
        mock_email_alerter.send.assert_called_once()