"""
Algorithm Mode Whitelist Condition - Validates cryptographic modes for algorithms.

Ensures algorithms use approved modes and avoids forbidden modes.
Example: AES must use GCM or CTR, not ECB or CBC.
"""

from typing import Any, Dict, List
import logging
from policy.conditions.base_condition import BaseCondition

logger = logging.getLogger(__name__)


class AlgorithmModeWhitelistCondition(BaseCondition):
    """
    Condition that validates algorithm modes.
    
    Example:
        parameters = {
            "algorithm": "AES",
            "approved_modes": ["GCM", "CTR", "CCM"],
            "forbidden_modes": ["ECB", "CBC"]
        }
        
        AES/GCM/NoPadding → PASS
        AES/ECB/NoPadding → FAIL (forbidden)
        AES/CBC/NoPadding → FAIL (forbidden)
        AES with no mode specified → WARN
    """

    def _validate_parameters(self) -> None:
        """Ensure algorithm is present, and modes are lists."""
        if "algorithm" not in self.parameters:
            raise ValueError("Missing required parameter: algorithm")
        
        # Normalize algorithm to uppercase
        self.parameters["algorithm"] = self.parameters["algorithm"].upper()
        
        approved = self.parameters.get("approved_modes", [])
        forbidden = self.parameters.get("forbidden_modes", [])
        
        if not isinstance(approved, list):
            raise TypeError("approved_modes must be a list")
        
        if not isinstance(forbidden, list):
            raise TypeError("forbidden_modes must be a list")
        
        # Normalize modes to uppercase
        self.parameters["approved_modes"] = [
            m.upper() if isinstance(m, str) else m
            for m in approved
        ]
        self.parameters["forbidden_modes"] = [
            m.upper() if isinstance(m, str) else m
            for m in forbidden
        ]
        
        # Warn if both approved and forbidden are empty
        if len(approved) == 0 and len(forbidden) == 0:
            logger.warning(
                "Mode whitelist has both approved and forbidden empty",
                extra={"algorithm": self.parameters["algorithm"]}
            )

    def evaluate(self, evidence_data: Dict[str, Any]) -> tuple[str, str]:
        """
        Evaluate if algorithm mode is acceptable.
        
        Args:
            evidence_data: Must contain 'algorithm' and optionally 'mode'
        
        Returns:
            (result, message) tuple
        """
        try:
            # Extract algorithm
            algorithm = self._get_evidence_field(
                evidence_data,
                "algorithm",
                required=True
            )
            
            algo_normalized = str(algorithm).upper()
            target_algo = self.parameters["algorithm"]
            
            # Only evaluate for matching algorithm
            if algo_normalized != target_algo:
                message = (
                    f"Mode whitelist applies to {target_algo} only. "
                    f"Found {algorithm} - not evaluated"
                )
                logger.debug(
                    "Mode whitelist condition skipped",
                    extra={
                        "expected_algorithm": target_algo,
                        "found_algorithm": algo_normalized
                    }
                )
                return ("PASS", message)
            
            # Extract mode
            mode = self._get_evidence_field(
                evidence_data,
                "mode",
                required=False,
                default=None
            )
            
            if mode is None:
                message = (
                    f"{algorithm} algorithm found but mode is not specified. "
                    f"Cannot validate against whitelist"
                )
                logger.warning(
                    "Mode not specified for algorithm requiring mode validation",
                    extra={"algorithm": algorithm}
                )
                return ("WARN", message)
            
            mode_normalized = str(mode).upper()
            approved_modes = self.parameters.get("approved_modes", [])
            forbidden_modes = self.parameters.get("forbidden_modes", [])
            
            # Check forbidden modes first (takes precedence)
            if mode_normalized in forbidden_modes:
                message = (
                    f"{algorithm} mode {mode} is explicitly forbidden. "
                    f"Forbidden modes: {', '.join(forbidden_modes)}"
                )
                logger.info(
                    "Algorithm mode is forbidden",
                    extra={
                        "algorithm": algorithm,
                        "mode": mode,
                        "forbidden_modes": forbidden_modes
                    }
                )
                return ("FAIL", message)
            
            # Check approved modes (if list is non-empty)
            if len(approved_modes) > 0:
                if mode_normalized in approved_modes:
                    message = (
                        f"{algorithm} mode {mode} is approved"
                    )
                    logger.debug(
                        "Algorithm mode is approved",
                        extra={"algorithm": algorithm, "mode": mode}
                    )
                    return ("PASS", message)
                else:
                    message = (
                        f"{algorithm} mode {mode} is not in approved list. "
                        f"Approved modes: {', '.join(approved_modes)}"
                    )
                    logger.info(
                        "Algorithm mode not in approved list",
                        extra={
                            "algorithm": algorithm,
                            "mode": mode,
                            "approved_modes": approved_modes
                        }
                    )
                    return ("FAIL", message)
            
            # If no approved modes specified and not forbidden, pass
            message = (
                f"{algorithm} mode {mode} is not forbidden"
            )
            logger.debug("Mode check passed", extra={
                "algorithm": algorithm,
                "mode": mode
            })
            return ("PASS", message)
        
        except KeyError as e:
            message = f"Missing required evidence field: {str(e)}"
            logger.error(message)
            return ("WARN", message)
        
        except Exception as e:
            message = f"Unexpected error during evaluation: {str(e)}"
            logger.error(message, exc_info=True)
            return ("WARN", message)