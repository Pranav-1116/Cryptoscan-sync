# services/drift/drift/core/detector.py

"""
Production drift detector - identifies cryptographic changes between scans.
Implements fingerprinting and change detection algorithms.
"""

import logging
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


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
        """
        Generate unique signature for comparison.
        Used to detect if same crypto moved or if it's different.
        """
        return f"{self.algorithm}|{self.key_size}|{self.mode}|{self.purpose}|{self.file_path}|{self.line_number}"
    
    def to_semantic_signature(self) -> str:
        """
        Semantic signature (ignores location).
        Used to detect same crypto in different location.
        """
        return f"{self.algorithm}|{self.key_size}|{self.mode}|{self.purpose}"


@dataclass
class DriftChange:
    """Represents a single cryptographic change."""
    change_type: str  # NEW, REMOVED, UPGRADED, DOWNGRADED, MOVED
    baseline_fingerprint: Optional[CryptoFingerprint]
    current_fingerprint: Optional[CryptoFingerprint]
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    reason: str
    
    @property
    def affected_algorithm(self) -> str:
        """Get algorithm name (from current or baseline)."""
        if self.current_fingerprint:
            return self.current_fingerprint.algorithm
        return self.baseline_fingerprint.algorithm


@dataclass
class DriftDetectionResult:
    """Complete drift detection result."""
    changes: List[DriftChange] = field(default_factory=list)
    baseline_scan_id: str = ""
    current_scan_id: str = ""
    detected_at: datetime = field(default_factory=datetime.utcnow)
    
    @property
    def total_changes(self) -> int:
        """Total number of changes detected."""
        return len(self.changes)
    
    @property
    def critical_changes(self) -> List[DriftChange]:
        """Filter critical changes."""
        return [c for c in self.changes if c.severity == "CRITICAL"]
    
    @property
    def high_changes(self) -> List[DriftChange]:
        """Filter high severity changes."""
        return [c for c in self.changes if c.severity == "HIGH"]


class DriftDetector:
    """
    Production drift detector using fingerprinting and comparison.
    Identifies cryptographic changes between baseline and current scans.
    """
    
    def __init__(self):
        """Initialize drift detector."""
        pass
    
    def detect_drift(
        self,
        baseline_findings: List[Dict],
        current_findings: List[Dict],
        baseline_scan_id: str,
        current_scan_id: str,
    ) -> DriftDetectionResult:
        """
        Detect cryptographic drift between two scans.
        
        Args:
            baseline_findings: Findings from baseline scan
            current_findings: Findings from current scan
            baseline_scan_id: ID of baseline scan
            current_scan_id: ID of current scan
        
        Returns:
            DriftDetectionResult with all detected changes
        """
        logger.info(
            f"Detecting drift: baseline {baseline_scan_id} vs "
            f"current {current_scan_id}"
        )
        
        # Convert findings to fingerprints
        baseline_fps = self._findings_to_fingerprints(baseline_findings)
        current_fps = self._findings_to_fingerprints(current_findings)
        
        # Create index by signature for comparison
        baseline_index = {fp.to_signature(): fp for fp in baseline_fps}
        current_index = {fp.to_signature(): fp for fp in current_fps}
        
        # Create semantic index (ignores location)
        baseline_semantic = {fp.to_semantic_signature(): fp for fp in baseline_fps}
        current_semantic = {fp.to_semantic_signature(): fp for fp in current_fps}
        
        result = DriftDetectionResult(
            baseline_scan_id=baseline_scan_id,
            current_scan_id=current_scan_id,
        )
        
        # Detect REMOVED (in baseline, not in current)
        for sig, baseline_fp in baseline_index.items():
            if sig not in current_index:
                # Check if it moved (same crypto, different location)
                semantic_sig = baseline_fp.to_semantic_signature()
                
                if semantic_sig in current_semantic:
                    # Moved, not removed
                    current_fp = current_semantic[semantic_sig]
                    result.changes.append(DriftChange(
                        change_type="MOVED",
                        baseline_fingerprint=baseline_fp,
                        current_fingerprint=current_fp,
                        severity="INFO",
                        reason=f"Crypto moved from {baseline_fp.file_path}:{baseline_fp.line_number} "
                               f"to {current_fp.file_path}:{current_fp.line_number}",
                    ))
                else:
                    # Truly removed
                    result.changes.append(DriftChange(
                        change_type="REMOVED",
                        baseline_fingerprint=baseline_fp,
                        current_fingerprint=None,
                        severity=self._calculate_removal_severity(baseline_fp),
                        reason=f"Cryptographic use removed: {baseline_fp.algorithm} "
                               f"at {baseline_fp.file_path}:{baseline_fp.line_number}",
                    ))
        
        # Detect NEW (in current, not in baseline)
        for sig, current_fp in current_index.items():
            if sig not in baseline_index:
                # Check if it moved
                semantic_sig = current_fp.to_semantic_signature()
                
                if semantic_sig not in baseline_semantic:
                    # Truly new
                    result.changes.append(DriftChange(
                        change_type="NEW",
                        baseline_fingerprint=None,
                        current_fingerprint=current_fp,
                        severity=self._calculate_new_severity(current_fp),
                        reason=f"New cryptographic use: {current_fp.algorithm} "
                               f"at {current_fp.file_path}:{current_fp.line_number}",
                    ))
        
        # Detect UPGRADES/DOWNGRADES (same algorithm, different parameters)
        for semantic_sig, baseline_fp in baseline_semantic.items():
            if semantic_sig in current_semantic:
                current_fp = current_semantic[semantic_sig]
                
                # Skip if exact same (already would be in baseline_index)
                if baseline_fp.to_signature() == current_fp.to_signature():
                    continue
                
                # Compare key sizes
                if baseline_fp.key_size and current_fp.key_size:
                    if current_fp.key_size > baseline_fp.key_size:
                        result.changes.append(DriftChange(
                            change_type="UPGRADED",
                            baseline_fingerprint=baseline_fp,
                            current_fingerprint=current_fp,
                            severity="INFO",
                            reason=f"{baseline_fp.algorithm} key size upgraded: "
                                   f"{baseline_fp.key_size} → {current_fp.key_size}",
                        ))
                    elif current_fp.key_size < baseline_fp.key_size:
                        result.changes.append(DriftChange(
                            change_type="DOWNGRADED",
                            baseline_fingerprint=baseline_fp,
                            current_fingerprint=current_fp,
                            severity="CRITICAL",
                            reason=f"{baseline_fp.algorithm} key size DOWNGRADED: "
                                   f"{baseline_fp.key_size} → {current_fp.key_size}",
                        ))
        
        logger.info(
            f"Drift detection complete: {result.total_changes} changes detected "
            f"({len(result.critical_changes)} CRITICAL, "
            f"{len(result.high_changes)} HIGH)"
        )
        
        return result
    
    def _findings_to_fingerprints(self, findings: List[Dict]) -> List[CryptoFingerprint]:
        """
        Convert raw findings to fingerprints.
        
        Args:
            findings: List of finding dictionaries
        
        Returns:
            List of CryptoFingerprint objects
        """
        fingerprints = []
        
        for finding in findings:
            try:
                fp = CryptoFingerprint(
                    algorithm=finding.get("algorithm", "UNKNOWN"),
                    key_size=finding.get("key_size"),
                    mode=finding.get("mode"),
                    purpose=finding.get("purpose", "UNKNOWN"),
                    file_path=finding.get("file_path", ""),
                    line_number=finding.get("line_number", 0),
                )
                fingerprints.append(fp)
            except Exception as e:
                logger.warning(f"Failed to convert finding to fingerprint: {e}")
        
        return fingerprints
    
    def _calculate_removal_severity(self, fingerprint: CryptoFingerprint) -> str:
        """
        Calculate severity of removing a crypto asset.
        
        Args:
            fingerprint: Removed crypto fingerprint
        
        Returns:
            Severity level
        """
        # Removal of strong crypto = informational
        # Removal of weak crypto = informational (good!)
        # Removal of critical business process = high
        
        if fingerprint.purpose in ["SIGNING", "KEY_EXCHANGE"]:
            return "HIGH"
        
        return "INFO"
    
    def _calculate_new_severity(self, fingerprint: CryptoFingerprint) -> str:
        """
        Calculate severity of introducing new crypto.
        
        Args:
            fingerprint: New crypto fingerprint
        
        Returns:
            Severity level
        """
        # New weak crypto = CRITICAL
        weak_algorithms = ["DES", "MD5", "SHA1", "RC4"]
        
        if fingerprint.algorithm in weak_algorithms:
            return "CRITICAL"
        
        # New algo without known strength = MEDIUM
        return "MEDIUM"