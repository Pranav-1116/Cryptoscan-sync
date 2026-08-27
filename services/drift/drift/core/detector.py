"""
Drift detector — fingerprint comparison plus the inventory/comparator API.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from drift.classifiers.severity_calculator import SeverityCalculator
from drift.core.comparator import Comparator, ComparisonResult
from drift.fingerprinting.inventory_builder import InventoryBuilder
from drift.models.drift_summary import DriftSummary

logger = logging.getLogger(__name__)


@dataclass
class BaselineInfo:
    baseline_id: UUID
    approved_scan_id: UUID
    approved_by: str
    approved_at: datetime
    system_identifier: str
    environment: str = "prod"


@dataclass
class DetectionRunResult:
    success: bool
    drift_detected: bool
    no_baseline_exists: bool = False
    comparison_result: Optional[ComparisonResult] = None
    drift_summary: Optional[DriftSummary] = None


@dataclass
class CryptoFingerprint:
    """Cryptographic asset fingerprint for comparison."""

    algorithm: str
    key_size: Optional[int]
    mode: Optional[str]
    purpose: str
    file_path: str
    line_number: int

    def to_signature(self) -> str:
        return (
            f"{self.algorithm}|{self.key_size}|{self.mode}|"
            f"{self.purpose}|{self.file_path}|{self.line_number}"
        )

    def to_semantic_signature(self) -> str:
        return f"{self.algorithm}|{self.key_size}|{self.mode}|{self.purpose}"


@dataclass
class DriftChange:
    change_type: str
    baseline_fingerprint: Optional[CryptoFingerprint]
    current_fingerprint: Optional[CryptoFingerprint]
    severity: str
    reason: str

    @property
    def affected_algorithm(self) -> str:
        if self.current_fingerprint:
            return self.current_fingerprint.algorithm
        return self.baseline_fingerprint.algorithm


@dataclass
class DriftDetectionResult:
    changes: List[DriftChange] = field(default_factory=list)
    baseline_scan_id: str = ""
    current_scan_id: str = ""
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def total_changes(self) -> int:
        return len(self.changes)

    @property
    def critical_changes(self) -> List[DriftChange]:
        return [c for c in self.changes if c.severity == "CRITICAL"]

    @property
    def high_changes(self) -> List[DriftChange]:
        return [c for c in self.changes if c.severity == "HIGH"]


class DriftDetector:
    """
    Dual API:
      - detect_drift(...) used by the worker and simple unit tests
      - detect(...) async inventory/comparator flow used by integration tests
    """

    def __init__(
        self,
        inventory_builder: InventoryBuilder | None = None,
        comparator: Comparator | None = None,
        alert_dispatcher=None,
        **kwargs,
    ) -> None:
        self._inventory_builder = inventory_builder
        self._comparator = comparator
        self._alert_dispatcher = alert_dispatcher
        self._severity = SeverityCalculator()

    async def detect(
        self,
        current_scan_id: UUID,
        system_identifier: str,
        baseline_info: BaselineInfo | None,
        baseline_evidence_records: list[dict[str, Any]] | None = None,
        current_evidence_records: list[dict[str, Any]] | None = None,
        notification_emails: list[str] | None = None,
    ) -> DetectionRunResult:
        if baseline_info is None:
            return DetectionRunResult(
                success=True,
                drift_detected=False,
                no_baseline_exists=True,
            )

        builder = self._inventory_builder or InventoryBuilder()
        comparator = self._comparator or Comparator()
        baseline_inv = builder.build(
            scan_id=baseline_info.approved_scan_id,
            evidence_records=baseline_evidence_records or [],
        )
        current_inv = builder.build(
            scan_id=current_scan_id,
            evidence_records=current_evidence_records or [],
        )
        comparison = comparator.compare(
            baseline=baseline_inv,
            current=current_inv,
            system_identifier=system_identifier,
        )
        summary = comparison.summary

        if comparison.has_drift and self._alert_dispatcher is not None:
            await self._alert_dispatcher.dispatch(
                drift_summary=summary,
                drift_events=comparison.drift_events,
                notification_emails=notification_emails or [],
                scan_id=current_scan_id,
                system_identifier=system_identifier,
            )

        return DetectionRunResult(
            success=True,
            drift_detected=comparison.has_drift,
            comparison_result=comparison,
            drift_summary=summary,
        )

    def detect_drift(
        self,
        baseline_findings: List[Dict],
        current_findings: List[Dict],
        baseline_scan_id: str,
        current_scan_id: str,
    ) -> DriftDetectionResult:
        logger.info(
            "Detecting drift: baseline %s vs current %s",
            baseline_scan_id,
            current_scan_id,
        )

        baseline_fps = self._findings_to_fingerprints(baseline_findings)
        current_fps = self._findings_to_fingerprints(current_findings)

        baseline_index = {fp.to_signature(): fp for fp in baseline_fps}
        current_index = {fp.to_signature(): fp for fp in current_fps}
        baseline_semantic = {fp.to_semantic_signature(): fp for fp in baseline_fps}
        current_semantic = {fp.to_semantic_signature(): fp for fp in current_fps}
        baseline_loc = {(fp.file_path, fp.line_number): fp for fp in baseline_fps}
        current_loc = {(fp.file_path, fp.line_number): fp for fp in current_fps}

        result = DriftDetectionResult(
            baseline_scan_id=baseline_scan_id,
            current_scan_id=current_scan_id,
        )

        changed_locations: set[tuple[str, int]] = set()
        weak = {"DES", "3DES", "RC4", "MD5", "SHA-1", "SHA1", "RC2"}
        for loc, baseline_fp in baseline_loc.items():
            current_fp = current_loc.get(loc)
            if current_fp is None:
                continue
            algo_changed = baseline_fp.algorithm != current_fp.algorithm
            mode_changed = (baseline_fp.mode or "") != (current_fp.mode or "")
            key_changed = baseline_fp.key_size != current_fp.key_size
            if not (algo_changed or mode_changed or key_changed):
                continue
            if algo_changed or mode_changed:
                result.changes.append(
                    DriftChange(
                        change_type="CHANGED",
                        baseline_fingerprint=baseline_fp,
                        current_fingerprint=current_fp,
                        severity="CRITICAL" if current_fp.algorithm in weak else "HIGH",
                        reason=(
                            f"Crypto changed at {loc[0]}:{loc[1]}: "
                            f"{baseline_fp.algorithm}/{baseline_fp.mode or '-'} "
                            f"→ {current_fp.algorithm}/{current_fp.mode or '-'}"
                        ),
                    )
                )
                changed_locations.add(loc)
            elif baseline_fp.key_size and current_fp.key_size:
                upgraded = current_fp.key_size > baseline_fp.key_size
                result.changes.append(
                    DriftChange(
                        change_type="UPGRADED" if upgraded else "DOWNGRADED",
                        baseline_fingerprint=baseline_fp,
                        current_fingerprint=current_fp,
                        severity="INFO" if upgraded else "CRITICAL",
                        reason=(
                            f"{baseline_fp.algorithm} key size "
                            f"{'upgraded' if upgraded else 'DOWNGRADED'}: "
                            f"{baseline_fp.key_size} → {current_fp.key_size}"
                        ),
                    )
                )
                changed_locations.add(loc)

        for sig, baseline_fp in baseline_index.items():
            if (baseline_fp.file_path, baseline_fp.line_number) in changed_locations:
                continue
            if sig not in current_index:
                semantic_sig = baseline_fp.to_semantic_signature()
                if semantic_sig in current_semantic:
                    current_fp = current_semantic[semantic_sig]
                    result.changes.append(
                        DriftChange(
                            change_type="MOVED",
                            baseline_fingerprint=baseline_fp,
                            current_fingerprint=current_fp,
                            severity="INFO",
                            reason=(
                                f"Crypto moved from {baseline_fp.file_path}:{baseline_fp.line_number} "
                                f"to {current_fp.file_path}:{current_fp.line_number}"
                            ),
                        )
                    )
                else:
                    result.changes.append(
                        DriftChange(
                            change_type="REMOVED",
                            baseline_fingerprint=baseline_fp,
                            current_fingerprint=None,
                            severity=self._calculate_removal_severity(baseline_fp),
                            reason=(
                                f"Cryptographic use removed: {baseline_fp.algorithm} "
                                f"at {baseline_fp.file_path}:{baseline_fp.line_number}"
                            ),
                        )
                    )

        for sig, current_fp in current_index.items():
            if (current_fp.file_path, current_fp.line_number) in changed_locations:
                continue
            if sig not in baseline_index:
                semantic_sig = current_fp.to_semantic_signature()
                if semantic_sig not in baseline_semantic:
                    result.changes.append(
                        DriftChange(
                            change_type="NEW",
                            baseline_fingerprint=None,
                            current_fingerprint=current_fp,
                            severity=self._calculate_new_severity(current_fp),
                            reason=(
                                f"New cryptographic use: {current_fp.algorithm} "
                                f"at {current_fp.file_path}:{current_fp.line_number}"
                            ),
                        )
                    )

        # Weak-algorithm spread: a *new occurrence* of an algorithm that already
        # existed in the baseline is suppressed by the semantic-signature check
        # above (noise reduction). For broken/deprecated algorithms that silence
        # is dangerous — flag the spread as a single aggregated event.
        baseline_semantic_counts: dict[str, int] = {}
        current_semantic_counts: dict[str, int] = {}
        for fp in baseline_fps:
            baseline_semantic_counts[fp.to_semantic_signature()] = (
                baseline_semantic_counts.get(fp.to_semantic_signature(), 0) + 1
            )
        for fp in current_fps:
            current_semantic_counts[fp.to_semantic_signature()] = (
                current_semantic_counts.get(fp.to_semantic_signature(), 0) + 1
            )
        spread_reported: set[str] = set()
        for sig, count in current_semantic_counts.items():
            base_count = baseline_semantic_counts.get(sig, 0)
            # Only flag spread of an algorithm that already existed (base_count >= 1).
            # Entirely-new algorithms are handled by the NEW path above.
            if count <= base_count or base_count == 0 or sig in spread_reported:
                continue
            sample = current_semantic.get(sig)
            if sample is None or sample.algorithm not in weak:
                continue
            spread_reported.add(sig)
            result.changes.append(
                DriftChange(
                    change_type="NEW",
                    baseline_fingerprint=None,
                    current_fingerprint=sample,
                    severity="HIGH",
                    reason=(
                        f"Weak algorithm spread: {sample.algorithm} occurrences grew "
                        f"{base_count} → {count} (e.g. {sample.file_path}:{sample.line_number})"
                    ),
                )
            )

        for semantic_sig, baseline_fp in baseline_semantic.items():
            if semantic_sig in current_semantic:
                current_fp = current_semantic[semantic_sig]
                if baseline_fp.to_signature() == current_fp.to_signature():
                    continue
                if baseline_fp.key_size and current_fp.key_size:
                    if current_fp.key_size > baseline_fp.key_size:
                        result.changes.append(
                            DriftChange(
                                change_type="UPGRADED",
                                baseline_fingerprint=baseline_fp,
                                current_fingerprint=current_fp,
                                severity="INFO",
                                reason=(
                                    f"{baseline_fp.algorithm} key size upgraded: "
                                    f"{baseline_fp.key_size} → {current_fp.key_size}"
                                ),
                            )
                        )
                    elif current_fp.key_size < baseline_fp.key_size:
                        result.changes.append(
                            DriftChange(
                                change_type="DOWNGRADED",
                                baseline_fingerprint=baseline_fp,
                                current_fingerprint=current_fp,
                                severity="CRITICAL",
                                reason=(
                                    f"{baseline_fp.algorithm} key size DOWNGRADED: "
                                    f"{baseline_fp.key_size} → {current_fp.key_size}"
                                ),
                            )
                        )

        logger.info(
            "Drift detection complete: %s changes (%s CRITICAL, %s HIGH)",
            result.total_changes,
            len(result.critical_changes),
            len(result.high_changes),
        )
        return result

    def _findings_to_fingerprints(self, findings: List[Dict]) -> List[CryptoFingerprint]:
        fingerprints = []
        for finding in findings:
            try:
                fingerprints.append(
                    CryptoFingerprint(
                        algorithm=finding.get("algorithm", "UNKNOWN"),
                        key_size=finding.get("key_size"),
                        mode=finding.get("mode"),
                        purpose=finding.get("purpose", "UNKNOWN"),
                        file_path=finding.get("file_path", ""),
                        line_number=finding.get("line_number", 0),
                    )
                )
            except Exception as exc:
                logger.warning("Failed to convert finding to fingerprint: %s", exc)
        return fingerprints

    def _calculate_removal_severity(self, fingerprint: CryptoFingerprint) -> str:
        severity = self._severity.calculate_for_removed_crypto(fingerprint)
        return getattr(severity, "value", str(severity))

    def _calculate_new_severity(self, fingerprint: CryptoFingerprint) -> str:
        severity = self._severity.calculate_for_new_crypto(fingerprint)
        return getattr(severity, "value", str(severity))
