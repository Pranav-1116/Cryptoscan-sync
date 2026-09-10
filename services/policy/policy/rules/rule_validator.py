"""
Rule Validator - Validates policy rules for correctness.

Ensures rules are well-formed and can be safely evaluated.
"""

import logging
from datetime import datetime

from policy.models.policy_rule import PolicyRule, RuleType, Severity

logger = logging.getLogger(__name__)


class RuleValidator:
    """Validates policy rules."""

    def validate(self, rule: PolicyRule) -> bool:
        """
        Validate a rule for correctness and safety.
        
        Args:
            rule: PolicyRule to validate
        
        Returns:
            True if valid
        
        Raises:
            ValueError: If rule is invalid
        """
        logger.debug(f"Validating rule: {rule.rule_id}")
        
        # Basic structure checks
        self._validate_basic_structure(rule)
        
        # Condition-specific checks
        self._validate_condition(rule)
        
        # Metadata checks
        self._validate_metadata(rule)
        
        logger.debug(f"Rule {rule.rule_id} is valid")
        return True

    def _validate_basic_structure(self, rule: PolicyRule) -> None:
        """Validate basic rule structure."""
        if not rule.rule_id:
            raise ValueError("rule_id is required")
        
        if not rule.rule_name:
            raise ValueError("rule_name is required")
        
        if not rule.description:
            raise ValueError("description is required")
        
        if not rule.remediation:
            raise ValueError("remediation is required")
        
        # Check rule_id format (should be UPPERCASE-NNN)
        if not self._is_valid_rule_id_format(rule.rule_id):
            logger.warning(
                f"Rule ID {rule.rule_id} doesn't follow recommended format"
            )

    def _is_valid_rule_id_format(self, rule_id: str) -> bool:
        """Check if rule ID follows recommended format."""
        import re
        return bool(re.match(r"^[A-Z0-9]+-[0-9]{3,}$", rule_id))

    def _validate_condition(self, rule: PolicyRule) -> None:
        """Validate rule condition."""
        if not rule.condition:
            raise ValueError("condition is required")
        
        if not rule.condition.type:
            raise ValueError("condition.type is required")
        
        if not rule.condition.parameters:
            raise ValueError("condition.parameters is required")
        
        # Validate based on condition type
        condition_type = rule.condition.type
        parameters = rule.condition.parameters
        
        if condition_type == RuleType.ALGORITHM_IN_LIST:
            if "algorithm_list" not in parameters:
                raise ValueError(
                    "ALGORITHM_IN_LIST requires algorithm_list parameter"
                )
            if not isinstance(parameters["algorithm_list"], list):
                raise ValueError("algorithm_list must be a list")
            if len(parameters["algorithm_list"]) == 0:
                raise ValueError("algorithm_list cannot be empty")
        
        elif condition_type == RuleType.KEY_SIZE_MINIMUM:
            if "algorithm" not in parameters:
                raise ValueError("KEY_SIZE_MINIMUM requires algorithm parameter")
            if "minimum_key_size" not in parameters:
                raise ValueError(
                    "KEY_SIZE_MINIMUM requires minimum_key_size parameter"
                )
            min_size = parameters["minimum_key_size"]
            if not isinstance(min_size, int) or min_size <= 0:
                raise ValueError("minimum_key_size must be positive integer")
        
        elif condition_type == RuleType.ALGORITHM_MODE_WHITELIST:
            if "algorithm" not in parameters:
                raise ValueError(
                    "ALGORITHM_MODE_WHITELIST requires algorithm parameter"
                )
            approved = parameters.get("approved_modes", [])
            forbidden = parameters.get("forbidden_modes", [])
            if len(approved) == 0 and len(forbidden) == 0:
                logger.warning(
                    f"Rule {rule.rule_id}: No approved or forbidden modes "
                    "specified - rule will pass all"
                )
        
        elif condition_type == RuleType.BOOLEAN_FLAG:
            if "field" not in parameters:
                raise ValueError("BOOLEAN_FLAG requires field parameter")
            if "forbidden_value" not in parameters:
                raise ValueError(
                    "BOOLEAN_FLAG requires forbidden_value parameter"
                )

    def _validate_metadata(self, rule: PolicyRule) -> None:
        """Validate rule metadata."""
        try:
            datetime.fromisoformat(rule.effective_date)
        except ValueError:
            raise ValueError(
                f"Invalid effective_date format: {rule.effective_date}. "
                "Must be ISO 8601 date"
            )
        
        if rule.severity not in [s.value for s in Severity]:
            raise ValueError(
                f"Invalid severity: {rule.severity}"
            )