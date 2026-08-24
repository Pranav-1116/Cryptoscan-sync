"""
Integration test: REMOVED_CRYPTO drift detection.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock
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


def make_record(
    algorithm: str,
    file_path: str,
    line_number: int,
    compliance_status: str = "PASS",
) -> dict:
    return {
        "evidence_id": str(uuid4()),
        "algorithm": algorithm,
        "file_path": file_path,
        "line_number": line_number,
        "class_name": "TestClass",
        "method_name": "testMethod",
        "compliance_status": compliance_status,
        "normalized_crypto": {
            "algorithm": algorithm,
            "nist_designation": "APPROVED" if compliance_status == "PASS" else "DISALLOWED",
        },
    }


@pytest.fixture
def mock_alerter():
    alerter = MagicMock(spec=EmailAlerter)
    alerter.send = AsyncMock()
    return alerter


@pytest.fixture
def detector(mock_alerter) -> DriftDetector:
    return DriftDetector(
        inventory_builder=InventoryBuilder(Fingerprinter()),
        comparator=Comparator(DriftTypeClassifier(), SeverityCalculator()),
        alert_dispatcher=AlertDispatcher(email_alerter=mock_alerter, max_retries=1),
    )


@pytest.fixture
def baseline_info() -> BaselineInfo:
    return BaselineInfo(
        baseline_id=uuid4(),
        approved_scan_id=uuid4(),
        approved_by="alice.security",
        approved_at=datetime.now(timezone.utc),
        system_identifier="https://github.com/org/app",
        environment="prod",
    )


class TestRemovedCryptoDetection:

    @pytest.mark.asyncio
    async def test_removed_compliant_crypto_is_medium(
        self,
        detector: DriftDetector,
        baseline_info: BaselineInfo,
        mock_alerter,
    ) -> None:
        """Removing compliant crypto = MEDIUM drift (worth noting)."""
        aes_record = make_record(
            algorithm="AES",
            file_path="src/main/Auth.java",
            line_number=75,
            compliance_status="PASS",
        )

        result = await detector.detect(
            current_scan_id=uuid4(),
            system_identifier=baseline_info.system_identifier,
            baseline_info=baseline_info,
            baseline_evidence_records=[aes_record],
            current_evidence_records=[],  # Removed
            notification_emails=["sec@example.com"],
        )

        assert result.success
        assert result.drift_detected

        event = result.comparison_result.drift_events[0]
        assert event.drift_type == DriftType.REMOVED_CRYPTO
        assert event.severity == DriftSeverity.MEDIUM

        # MEDIUM doesn't trigger email
        mock_alerter.send.assert_not_called()

    @pytest.mark.asyncio
    async def test_removed_noncompliant_crypto_is_info(
        self,
        detector: DriftDetector,
        baseline_info: BaselineInfo,
        mock_alerter,
    ) -> None:
        """Removing non-compliant crypto (e.g., DES) = INFO (positive)."""
        des_record = make_record(
            algorithm="DES",
            file_path="src/main/OldPayment.java",
            line_number=200,
            compliance_status="FAIL",
        )

        result = await detector.detect(
            current_scan_id=uuid4(),
            system_identifier=baseline_info.system_identifier,
            baseline_info=baseline_info,
            baseline_evidence_records=[des_record],
            current_evidence_records=[],  # DES removed (good!)
            notification_emails=["sec@example.com"],
        )

        assert result.success
        assert result.drift_detected

        event = result.comparison_result.drift_events[0]
        assert event.drift_type == DriftType.REMOVED_CRYPTO
        assert event.severity == DriftSeverity.INFO

        # INFO doesn't trigger email
        mock_alerter.send.assert_not_called()