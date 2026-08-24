"""
Comparator — compares baseline and current crypto inventories.

Detects differences and produces DriftEvent objects.
Production-level with full type safety and structured logging.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

import structlog

from drift.classifiers.drift_type_classifier import DriftTypeClassifier
from drift.classifiers.severity_calculator import SeverityCalculator
from drift.fingerprinting.inventory_builder import CryptoInventory
from drift.models.drift_event import DriftEvent, DriftSeverity, DriftType
from drift.models.drift_summary import DriftSummary

logger = structlog.get_logger(__name__)


@dataclass
class ComparisonResult:
    """Full result of comparing baseline vs current inventory."""
    baseline_id: UUID
    current_scan_id: UUID
    system_identifier: str
    drift_events: list[DriftEvent] = field(default_factory=list)

    @property
    def summary(self) -> DriftSummary:
        """Build DriftSummary from collected drift events."""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "INFO": 0}
        new_count = 0
        removed_count = 0

        for event in self.drift_events:
            severity_key = event.severity.value
            counts[severity_key] = counts.get(severity_key, 0) + 1

            if event.drift_type == DriftType.NEW_CRYPTO:
                new_count += 1
            elif event.drift_type == DriftType.REMOVED_CRYPTO:
                removed_count += 1

        return DriftSummary(
            baseline_id=self.baseline_id,
            current_scan_id=self.current_scan_id,
            system_identifier=self.system_identifier,
            critical=counts["CRITICAL"],
            high=counts["HIGH"],
            medium=counts["MEDIUM"],
            info=counts["INFO"],
            new_crypto_count=new_count,
            removed_crypto_count=removed_count,
        )

    @property
    def has_drift(self) -> bool:
        return len(self.drift_events) > 0


class Comparator:
    """
    Compares two CryptoInventory objects to detect drift.

    Algorithm:
    1. Compute set difference: current - baseline = NEW
    2. Compute set difference: baseline - current = REMOVED
    3. For each difference, classify type and severity
    4. Return ComparisonResult with all drift events
    """

    def __init__(
        self,
        type_classifier: DriftTypeClassifier | None = None,
        severity_calculator: SeverityCalculator | None = None,
    ) -> None:
        self._type_classifier = type_classifier or DriftTypeClassifier()
        self._severity_calculator = severity_calculator or SeverityCalculator()

    def compare(
        self,
        baseline: CryptoInventory,
        current: CryptoInventory,
        system_identifier: str,
    ) -> ComparisonResult:
        """
        Compare baseline and current inventories.

        Args:
            baseline: Approved baseline fingerprint inventory
            current: Current scan fingerprint inventory
            system_identifier: Repo URL or system name

        Returns:
            ComparisonResult with all detected drift events
        """
        log = logger.bind(
            baseline_scan_id=str(baseline.scan_id),
            current_scan_id=str(current.scan_id),
            system_identifier=system_identifier,
            baseline_count=baseline.total_count,
            current_count=current.total_count,
        )

        log.info("drift_comparison_started")

        result = ComparisonResult(
            baseline_id=baseline.scan_id,
            current_scan_id=current.scan_id,
            system_identifier=system_identifier,
        )

        baseline_hashes = baseline.hashes
        current_hashes = current.hashes

        # Detect NEW crypto (present in current, absent in baseline)
        new_hashes = current_hashes - baseline_hashes
        self._process_new_crypto(
            new_hashes=new_hashes,
            current=current,
            result=result,
        )

        # Detect REMOVED crypto (present in baseline, absent in current)
        removed_hashes = baseline_hashes - current_hashes
        self._process_removed_crypto(
            removed_hashes=removed_hashes,
            baseline=baseline,
            result=result,
        )

        # Note: CHANGED crypto detection is Month 3+ feature
        # Common hashes = same fingerprint in both = no drift

        log.info(
            "drift_comparison_completed",
            new_crypto=sum(
                1 for e in result.drift_events
                if e.drift_type == DriftType.NEW_CRYPTO
            ),
            removed_crypto=sum(
                1 for e in result.drift_events
                if e.drift_type == DriftType.REMOVED_CRYPTO
            ),
            total_drift_events=len(result.drift_events),
        )

        return result

    def _process_new_crypto(
        self,
        new_hashes: set[str],
        current: CryptoInventory,
        result: ComparisonResult,
    ) -> None:
        """Process all fingerprints new in current scan."""
        for fp_hash in new_hashes:
            current_fp = current.get_fingerprint(fp_hash)
            current_record = current.get_record(fp_hash)

            if current_fp is None or current_record is None:
                logger.warning(
                    "fingerprint_record_mismatch",
                    fp_hash=fp_hash[:16],
                )
                continue

            drift_type = self._type_classifier.classify_new(current_record)
            severity = self._severity_calculator.calculate_for_new_crypto(
                current_record
            )

            event = DriftEvent.new_crypto(
                baseline_id=result.baseline_id,
                current_scan_id=result.current_scan_id,
                algorithm=current_fp.algorithm,
                location=self._format_location(current_fp),
                severity=severity,
                current_state=self._extract_normalized_state(current_record),
                compliance_status=current_record.get("compliance_status"),
            )

            result.drift_events.append(event)

            logger.debug(
                "new_crypto_drift_event",
                drift_type=drift_type.value,
                severity=severity.value,
                algorithm=current_fp.algorithm,
                location=self._format_location(current_fp),
            )

    def _process_removed_crypto(
        self,
        removed_hashes: set[str],
        baseline: CryptoInventory,
        result: ComparisonResult,
    ) -> None:
        """Process all fingerprints removed from baseline."""
        for fp_hash in removed_hashes:
            baseline_fp = baseline.get_fingerprint(fp_hash)
            baseline_record = baseline.get_record(fp_hash)

            if baseline_fp is None or baseline_record is None:
                logger.warning(
                    "baseline_fingerprint_record_mismatch",
                    fp_hash=fp_hash[:16],
                )
                continue

            severity = self._severity_calculator.calculate_for_removed_crypto(
                baseline_record
            )

            event = DriftEvent.removed_crypto(
                baseline_id=result.baseline_id,
                current_scan_id=result.current_scan_id,
                algorithm=baseline_fp.algorithm,
                location=self._format_location(baseline_fp),
                baseline_state=self._extract_normalized_state(baseline_record),
            )

            result.drift_events.append(event)

            logger.debug(
                "removed_crypto_drift_event",
                severity=severity.value,
                algorithm=baseline_fp.algorithm,
                location=self._format_location(baseline_fp),
            )

    @staticmethod
    def _format_location(fp: Any) -> str:
        """Format location string from fingerprint."""
        if fp.file_path and fp.line_number:
            return f"{fp.file_path}:{fp.line_number}"
        if fp.file_path:
            return fp.file_path
        return "UNKNOWN"

    @staticmethod
    def _extract_normalized_state(record: dict[str, Any]) -> dict[str, Any]:
        """Extract normalized crypto state from record."""
        normalized = record.get("normalized_crypto")
        if isinstance(normalized, dict):
            return {
                "algorithm": normalized.get("algorithm"),
                "mode": normalized.get("mode"),
                "key_size": normalized.get("key_size"),
                "nist_designation": normalized.get("nist_designation"),
                "standard_name": normalized.get("standard_name"),
            }
        return {
            "algorithm": record.get("algorithm"),
            "mode": record.get("mode"),
            "key_size": record.get("key_size"),
        }