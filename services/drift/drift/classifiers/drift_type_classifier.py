"""
DriftTypeClassifier — determines the type of drift for detected changes.
"""

from __future__ import annotations

from typing import Any

import structlog

from drift.models.drift_event import DriftType

logger = structlog.get_logger(__name__)


class DriftTypeClassifier:
    """
    Classifies drift events into semantic types.

    Types (Month 2 implementation):
    - NEW_CRYPTO: Found in current scan but not in baseline
    - REMOVED_CRYPTO: Found in baseline but not in current scan

    Future types (Month 3+):
    - CHANGED_CRYPTO: Same location, different algorithm
    - DEGRADED_CRYPTO: Same algorithm, worse parameters (e.g., smaller key)
    """

    def classify_new(
        self, current_record: dict[str, Any]
    ) -> DriftType:
        """
        Classify a finding present in current but not in baseline.

        For Month 2, all such findings are NEW_CRYPTO.
        """
        return DriftType.NEW_CRYPTO

    def classify_removed(
        self, baseline_record: dict[str, Any]
    ) -> DriftType:
        """
        Classify a finding present in baseline but not in current.

        For Month 2, all such findings are REMOVED_CRYPTO.
        """
        return DriftType.REMOVED_CRYPTO

    def classify_changed(
        self,
        baseline_record: dict[str, Any],
        current_record: dict[str, Any],
    ) -> DriftType:
        """
        Classify a change at the same location.

        Determines whether it's CHANGED or DEGRADED.
        """
        baseline_algo = baseline_record.get("algorithm", "").upper()
        current_algo = current_record.get("algorithm", "").upper()

        # Same algorithm family — check if degraded
        if baseline_algo == current_algo:
            if self._is_degraded(baseline_record, current_record):
                return DriftType.DEGRADED_CRYPTO

        return DriftType.CHANGED_CRYPTO

    def _is_degraded(
        self,
        baseline: dict[str, Any],
        current: dict[str, Any],
    ) -> bool:
        """
        Check if a change represents a security degradation.

        Degradation = smaller key size, weaker mode, etc.
        """
        # Key size reduction
        baseline_key = baseline.get("key_size")
        current_key = current.get("key_size")

        if (
            isinstance(baseline_key, int)
            and isinstance(current_key, int)
            and current_key < baseline_key
        ):
            logger.debug(
                "key_size_reduction_detected",
                baseline_key_size=baseline_key,
                current_key_size=current_key,
            )
            return True

        # Mode downgrade (ECB < CBC < GCM)
        mode_security_rank = {
            "ECB": 0,
            "CBC": 1,
            "CFB": 2,
            "OFB": 2,
            "CTR": 3,
            "GCM": 4,
            "CCM": 4,
        }

        baseline_mode = str(baseline.get("mode", "")).upper()
        current_mode = str(current.get("mode", "")).upper()

        baseline_rank = mode_security_rank.get(baseline_mode, -1)
        current_rank = mode_security_rank.get(current_mode, -1)

        if (
            baseline_rank >= 0
            and current_rank >= 0
            and current_rank < baseline_rank
        ):
            return True

        return False