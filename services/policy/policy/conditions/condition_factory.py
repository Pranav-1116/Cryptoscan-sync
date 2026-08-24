"""
ConditionFactory — creates the correct condition evaluator
from a rule's condition type string.
"""

from __future__ import annotations

import logging

from policy.conditions.algorithm_in_list import AlgorithmInListCondition
from policy.conditions.algorithm_mode_whitelist import AlgorithmModeWhitelistCondition
from policy.conditions.base_condition import BaseCondition
from policy.conditions.boolean_flag import BooleanFlagCondition
from policy.conditions.complex_condition import ComplexCondition
from policy.conditions.key_size_minimum import KeySizeMinimumCondition
from policy.conditions.purpose_condition import PurposeCondition
from policy.conditions.timeline_condition import TimelineCondition

logger = logging.getLogger(__name__)

# Registry: condition_type → evaluator class
_CONDITION_REGISTRY: dict[str, type[BaseCondition]] = {
    "ALGORITHM_IN_LIST": AlgorithmInListCondition,
    "KEY_SIZE_MINIMUM": KeySizeMinimumCondition,
    "ALGORITHM_MODE_WHITELIST": AlgorithmModeWhitelistCondition,
    "BOOLEAN_FLAG": BooleanFlagCondition,
    "COMPLEX": ComplexCondition,
    "TIMELINE": TimelineCondition,
    "PURPOSE_IN_LIST": PurposeCondition,
}


class UnknownConditionTypeError(Exception):
    """Raised when a rule references an unknown condition type."""


class ConditionFactory:
    """
    Factory for creating condition evaluator instances.

    Instances are created fresh per evaluation call (stateless evaluators)
    or cached — conditions must be stateless and thread-safe.
    """

    def __init__(self) -> None:
        # Cache instances — conditions are stateless so one instance per type
        self._instances: dict[str, BaseCondition] = {}

    def create(self, condition_type: str) -> BaseCondition:
        """
        Return an evaluator instance for the given condition type.

        Args:
            condition_type: CONDITION_TYPE string from rule YAML.

        Returns:
            BaseCondition subclass instance.

        Raises:
            UnknownConditionTypeError: If type is not registered.
        """
        if condition_type not in _CONDITION_REGISTRY:
            raise UnknownConditionTypeError(
                f"Unknown condition type '{condition_type}'. "
                f"Registered types: {sorted(_CONDITION_REGISTRY.keys())}"
            )

        # Return cached instance (stateless, safe to share)
        if condition_type not in self._instances:
            cls = _CONDITION_REGISTRY[condition_type]
            self._instances[condition_type] = cls()
            logger.debug("Created condition evaluator: %s", condition_type)

        return self._instances[condition_type]

    @staticmethod
    def registered_types() -> list[str]:
        """Return sorted list of all registered condition types."""
        return sorted(_CONDITION_REGISTRY.keys())

    @staticmethod
    def register(condition_type: str, cls: type[BaseCondition]) -> None:
        """
        Register a new condition type (for plugins/extensions).

        Args:
            condition_type: String identifier for the condition.
            cls: BaseCondition subclass to register.
        """
        if not issubclass(cls, BaseCondition):
            raise TypeError(f"{cls} must be a subclass of BaseCondition")
        _CONDITION_REGISTRY[condition_type] = cls
        logger.info("Registered new condition type: %s → %s", condition_type, cls.__name__)