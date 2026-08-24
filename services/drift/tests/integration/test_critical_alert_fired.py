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
from drift.models.drift_event import DriftSeverity


@pytest.mark.asyncio
async def test_critical_alert_fired_for_new_des():
    alerter = MagicMock(spec=EmailAlerter)
    alerter.send = AsyncMock()
    detector = DriftDetector(
        inventory_builder=InventoryBuilder(Fingerprinter()),
        comparator=Comparator(DriftTypeClassifier(), SeverityCalculator()),
        alert_dispatcher=AlertDispatcher(email_alerter=alerter, max_retries=1),
    )
    baseline = BaselineInfo(
        baseline_id=uuid4(),
        approved_scan_id=uuid4(),
        approved_by="alice",
        approved_at=datetime.now(timezone.utc),
        system_identifier="https://github.com/org/app",
    )
    result = await detector.detect(
        current_scan_id=uuid4(),
        system_identifier=baseline.system_identifier,
        baseline_info=baseline,
        baseline_evidence_records=[],
        current_evidence_records=[
            {
                "evidence_id": str(uuid4()),
                "algorithm": "DES",
                "file_path": "P.java",
                "line_number": 1,
                "compliance_status": "FAIL",
            }
        ],
        notification_emails=["sec@example.com"],
    )
    assert result.drift_detected
    assert result.comparison_result.drift_events[0].severity == DriftSeverity.CRITICAL
    alerter.send.assert_called_once()
