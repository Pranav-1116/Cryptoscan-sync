"""
Boolean Flag Condition - Detects presence of critical flags.

Example: Fails if is_hardcoded_key is true.
"""

from typing import Any, Dict
import logging
from policy.conditions.base_condition import BaseCondition

logger = logging.getLogger(__name__)


class BooleanFlagCondition(BaseCondition):
    """
    Condition that fails if a boolean field equals forbidden value.
    
    Example:
        parameters = {
            "field": "is_hardcoded_key",
            "forbidden_value": true
        }
        
        Finding with is_hardcoded_key=true → FAIL
        Finding with is_hardcoded_key=false → PASS
    """

    def _validate_parameters(self) -> None:
        """Ensure field and forbidden_value are present."""
        if "field" not in self.parameters:
            raise ValueError("Missing required parameter: field")
        
        if "forbidden_value" not in self.parameters:
            raise ValueError("Missing required parameter: forbidden_value")
        
        # forbidden_value should be boolean
        forbidden = self.parameters["forbidden_value"]
        if not isinstance(forbidden, bool):
            logger.warning(
                f"forbidden_value should be boolean, got {type(forbidden)}. "
                f"Will coerce to boolean."
            )
            self.parameters["forbidden_value"] = bool(forbidden)

    def evaluate(self, evidence_data: Dict[str, Any]) -> tuple[str, str]:
        """
        Evaluate if boolean field matches forbidden value.
        
        Args:
            evidence_data: Must contain the specified field
        
        Returns:
            (result, message) tuple
        """
        try:
            field_name = self.parameters["field"]
            forbidden_value = self.parameters["forbidden_value"]
            
            # Extract field value
            field_value = self._get_evidence_field(
                evidence_data,
                field_name,
                required=False,
                default=None
            )
            
            if field_value is None:
                message = (
                    f"Field '{field_name}' not present in evidence. "
                    f"Treating as {not forbidden_value}"
                )
                logger.debug(
                    f"Boolean flag field not present",
                    extra={"field": field_name}
                )
                # If field is missing, treat as opposite of forbidden
                return ("PASS", message)
            
            # Coerce to boolean if needed
            try:
                field_bool = bool(field_value)
            except:
                message = f"Cannot convert field '{field_name}' value to boolean"
                logger.error(message)
                return ("WARN", message)
            
            # Check against forbidden value
            if field_bool == forbidden_value:
                message = (
                    f"Field '{field_name}' has value {field_bool}, "
                    f"which matches forbidden value {forbidden_value}"
                )
                logger.info(
                    "Boolean flag check failed",
                    extra={
                        "field": field_name,
                        "value": field_bool,
                        "forbidden": forbidden_value
                    }
                )
                return ("FAIL", message)
            else:
                message = (
                    f"Field '{field_name}' has value {field_bool}, "
                    f"which is acceptable"
                )
                logger.debug(
                    "Boolean flag check passed",
                    extra={"field": field_name, "value": field_bool}
                )
                return ("PASS", message)
        
        except Exception as e:
            message = f"Unexpected error during evaluation: {str(e)}"
            logger.error(message, exc_info=True)
            return ("WARN", message)