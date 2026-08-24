"""Policy rule models."""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class RuleType(str, Enum):
    ALGORITHM_IN_LIST = "ALGORITHM_IN_LIST"
    KEY_SIZE_MINIMUM = "KEY_SIZE_MINIMUM"
    ALGORITHM_MODE_WHITELIST = "ALGORITHM_MODE_WHITELIST"
    BOOLEAN_FLAG = "BOOLEAN_FLAG"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AlgorithmInListParameters(BaseModel):
    algorithm_list: list[str]


class AlgorithmInListParams(AlgorithmInListParameters):
    """Alias used by condition modules."""


class KeySizeMinimumParameters(BaseModel):
    algorithm: str
    minimum_key_size: int


class KeySizeMinimumParams(KeySizeMinimumParameters):
    """Alias used by condition modules."""


class AlgorithmModeWhitelistParameters(BaseModel):
    algorithm: str
    approved_modes: list[str] = Field(default_factory=list)
    forbidden_modes: list[str] = Field(default_factory=list)


class BooleanFlagParameters(BaseModel):
    field: str
    forbidden_value: bool = True


class Condition(BaseModel):
    type: str
    parameters: dict[str, Any] = Field(default_factory=dict)


class Evaluation(BaseModel):
    result_template: str = "FAIL"
    message_template: Optional[str] = None


class PolicyRule(BaseModel):
    rule_id: str
    rule_name: str
    version: str = "1.0"
    effective_date: str = "2024-01-01"
    severity: str = "HIGH"
    standard_reference: Optional[str] = None
    description: str = ""
    condition: Condition
    evaluation: Optional[Evaluation] = None
    remediation: str = ""
    enabled: bool = True
    scope: Optional[dict[str, Any]] = None

    model_config = {"extra": "allow"}


class PolicyRuleSet(BaseModel):
    rules: list[PolicyRule]
    metadata: Optional[dict[str, Any]] = None

    def get_rule_by_id(self, rule_id: str) -> Optional[PolicyRule]:
        for rule in self.rules:
            if rule.rule_id == rule_id:
                return rule
        return None

    def get_enabled_rules(self) -> list[PolicyRule]:
        return [rule for rule in self.rules if rule.enabled]
