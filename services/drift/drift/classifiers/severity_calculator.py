# services/drift/drift/classifiers/severity_calculator.py

"""
Production severity calculator for drift events.
Implements multi-factor severity assessment.
"""

import logging
from typing import Dict, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class Severity(str, Enum):
    """Severity levels for drift events."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class SeverityCalculator:
    """
    Multi-factor severity assessment for cryptographic drift.
    Considers: compliance impact, business impact, technical risk.
    """
    
    def __init__(self):
        """Initialize severity calculator with algorithm database."""
        self.weak_algorithms = {
            "DES": 4,
            "3DES": 3,
            "MD5": 4,
            "SHA1": 3,
            "RC4": 4,
            "ECB": 4,
        }
        
        self.strong_algorithms = {
            "AES": 0,
            "ChaCha20": 0,
            "SHA256": 0,
            "SHA512": 0,
            "RSA": 1,  # Depends on key size
            "ECDSA": 0,
        }
    
    def calculate_for_new_crypto(self, fingerprint, **kwargs) -> Severity:
        record = fingerprint if isinstance(fingerprint, dict) else None
        algorithm = (
            (record.get("algorithm") if record is not None else getattr(fingerprint, "algorithm", None))
            or "UNKNOWN"
        )
        key_size = record.get("key_size") if record is not None else getattr(fingerprint, "key_size", None)
        hardcoded = (
            bool(record.get("is_hardcoded_key"))
            if record is not None
            else bool(getattr(fingerprint, "is_hardcoded_key", False))
        )
        compliance = record.get("compliance_status") if record is not None else None
        if hardcoded:
            return Severity.CRITICAL
        from drift.core.algorithm_policy import is_weak

        if compliance == "FAIL" or is_weak(str(algorithm), key_size=key_size):
            return Severity.CRITICAL
        if compliance == "PASS":
            return Severity.MEDIUM
        return self.calculate_severity(str(algorithm), "NEW", key_size)

    def calculate_for_removed_crypto(self, fingerprint, **kwargs) -> Severity:
        record = fingerprint if isinstance(fingerprint, dict) else None
        algorithm = (
            (record.get("algorithm") if record is not None else getattr(fingerprint, "algorithm", None))
            or "UNKNOWN"
        )
        key_size = record.get("key_size") if record is not None else getattr(fingerprint, "key_size", None)
        compliance = record.get("compliance_status") if record is not None else None
        if compliance == "FAIL":
            return Severity.INFO
        if compliance == "PASS":
            return Severity.MEDIUM
        return self.calculate_severity(str(algorithm), "REMOVED", key_size)

    def calculate_severity(
        self,
        algorithm: str,
        change_type: str,
        key_size: Optional[int] = None,
        compliance_context: Optional[Dict] = None,
    ) -> Severity:
        """
        Calculate severity of cryptographic change.
        
        Args:
            algorithm: Algorithm name
            change_type: Type of change (NEW, REMOVED, UPGRADED, DOWNGRADED)
            key_size: Key size (if applicable)
            compliance_context: Compliance requirements (if available)
        
        Returns:
            Severity level
        """
        base_score = 0
        
        # Factor 1: Algorithm strength
        algo_upper = algorithm.upper()
        
        from drift.core.algorithm_policy import weakness_score

        registry_score = weakness_score(algo_upper, key_size=key_size)
        if registry_score:
            base_score += registry_score
        elif algo_upper in self.weak_algorithms:
            base_score += self.weak_algorithms[algo_upper]
        elif algo_upper in self.strong_algorithms:
            base_score += self.strong_algorithms[algo_upper]
        else:
            # Unknown algorithm
            base_score += 2  # Assume medium risk
        
        # Factor 2: Change type
        if change_type == "NEW":
            # New weak crypto = critical
            if base_score >= 3:
                return Severity.CRITICAL
            # New unknown or newly introduced approved crypto = medium
            return Severity.MEDIUM
        
        elif change_type == "DOWNGRADED":
            # Always critical
            return Severity.CRITICAL
        
        elif change_type == "UPGRADED":
            # Always positive
            return Severity.INFO
        
        elif change_type == "REMOVED":
            # Depends on what was removed
            if base_score >= 3:
                # Removed weak algo = good = info
                return Severity.INFO
            else:
                # Removed strong algo = bad = high
                return Severity.HIGH
        
        # Factor 3: Key size (if RSA/ECC)
        if key_size and algo_upper in ["RSA", "ECDSA", "EC"]:
            if key_size < 2048:
                base_score += 3  # Weak key size
            elif key_size >= 4096:
                base_score -= 1  # Strong key size
        
        # Convert score to severity
        return self._score_to_severity(base_score)
    
    def _score_to_severity(self, score: int) -> Severity:
        """
        Convert numeric score to severity level.
        
        Args:
            score: Numeric severity score
        
        Returns:
            Severity enum value
        """
        if score >= 4:
            return Severity.CRITICAL
        elif score >= 3:
            return Severity.HIGH
        elif score >= 2:
            return Severity.MEDIUM
        elif score >= 1:
            return Severity.LOW
        else:
            return Severity.INFO