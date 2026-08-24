"""
Policy Rule Models - Pydantic data models for cryptographic policy rules.

This module defines the structure of policy rules that are evaluated against
cryptographic findings. Rules are loaded from YAML files and validated against
this schema.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from datetime import datetime
from pydantic import BaseModel, Field, validator


class RuleType(str, Enum):
    """Enumeration of all supported condition types."""
    ALGORITHM_IN_LIST = "ALGORITHM_IN_LIST"
    KEY_SIZE_MINIMUM = "KEY_SIZE_MINIMUM"
    ALGORITHM_MODE_WHITELIST = "ALGORITHM_MODE_WHITELIST"
    BOOLEAN_FLAG = "BOOLEAN_FLAG"


class Severity(str, Enum):
    """Policy violation severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class EvaluationResult(str, Enum):
    """Possible evaluation outcomes."""
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"


class ConditionParameters(BaseModel):
    """Base class for condition-specific parameters."""
    
    class Config:
        extra = "allow"  # Allow extra fields for extensibility


class AlgorithmInListParameters(ConditionParameters):
    """Parameters for ALGORITHM_IN_LIST condition."""
    algorithm_list: List[str] = Field(
        ...,
        description="List of algorithms that trigger FAIL if found"
    )


class KeySizeMinimumParameters(ConditionParameters):
    """Parameters for KEY_SIZE_MINIMUM condition."""
    algorithm: str = Field(
        ...,
        description="Algorithm to check (e.g., 'RSA', 'ECC')"
    )
    minimum_key_size: int = Field(
        ...,
        ge=512,
        le=65536,
        description="Minimum acceptable key size in bits"
    )


class AlgorithmModeWhitelistParameters(ConditionParameters):
    """Parameters for ALGORITHM_MODE_WHITELIST condition."""
    algorithm: str = Field(
        ...,
        description="Algorithm to whitelist modes for"
    )
    approved_modes: List[str] = Field(
        default_factory=list,
        description="Approved modes (if present, only these pass)"
    )
    forbidden_modes: List[str] = Field(
        default_factory=list,
        description="Explicitly forbidden modes (always fail)"
    )


class BooleanFlagParameters(ConditionParameters):
    """Parameters for BOOLEAN_FLAG condition."""
    field: str = Field(
        ...,
        description="Evidence record field name to check"
    )
    forbidden_value: bool = Field(
        ...,
        description="If field equals this value, fail the check"
    )


class Condition(BaseModel):
    """Condition definition for a policy rule."""
    type: RuleType = Field(
        ...,
        description="Type of condition to evaluate"
    )
    parameters: Dict[str, Any] = Field(
        ...,
        description="Condition-specific parameters"
    )

    @validator("parameters", pre=True)
    def validate_parameters(cls, v: Dict[str, Any], values: Dict[str, Any]) -> Dict[str, Any]:
        """Validate parameters based on condition type."""
        if "type" not in values:
            return v
        
        condition_type = values["type"]
        
        # Map rule types to their parameter models
        parameter_models = {
            RuleType.ALGORITHM_IN_LIST: AlgorithmInListParameters,
            RuleType.KEY_SIZE_MINIMUM: KeySizeMinimumParameters,
            RuleType.ALGORITHM_MODE_WHITELIST: AlgorithmModeWhitelistParameters,
            RuleType.BOOLEAN_FLAG: BooleanFlagParameters,
        }
        
        if condition_type in parameter_models:
            try:
                parameter_models[condition_type](**v)
            except Exception as e:
                raise ValueError(f"Invalid parameters for {condition_type}: {str(e)}")
        
        return v


class Evaluation(BaseModel):
    """Evaluation logic (pseudo-code in YAML, logic in Python)."""
    result_template: str = Field(
        ...,
        description="Template for evaluation result (PASS/FAIL/WARN)"
    )
    message_template: Optional[str] = Field(
        None,
        description="Message template with placeholders"
    )


class PolicyRule(BaseModel):
    """Complete policy rule definition."""
    rule_id: str = Field(
        ...,
        regex="^[A-Z0-9]+-[0-9]{3,}$",  # BASELINE-001 format
        description="Unique rule identifier"
    )
    rule_name: str = Field(
        ...,
        min_length=3,
        max_length=200,
        description="Human-readable rule name"
    )
    version: str = Field(
        default="1.0",
        regex="^\\d+\\.\\d+$",
        description="Rule version in semver format"
    )
    effective_date: str = Field(
        ...,
        description="ISO 8601 date when rule becomes effective"
    )
    severity: Severity = Field(
        default=Severity.HIGH,
        description="Severity of violations"
    )
    standard_reference: Optional[str] = Field(
        None,
        description="Reference to security standard (NIST, PCI-DSS, etc.)"
    )
    description: str = Field(
        ...,
        min_length=10,
        description="Detailed rule description"
    )
    condition: Condition = Field(
        ...,
        description="Condition to evaluate"
    )
    evaluation: Evaluation = Field(
        ...,
        description="Evaluation logic"
    )
    remediation: str = Field(
        ...,
        min_length=10,
        description="Plain-language remediation guidance"
    )
    enabled: bool = Field(
        default=True,
        description="Whether this rule is active"
    )
    scope: Optional[Dict[str, Any]] = Field(
        None,
        description="Optional scope limiting (e.g., by environment, team)"
    )

    class Config:
        use_enum_values = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage/transmission."""
        return self.dict(by_alias=True)


class PolicyRuleSet(BaseModel):
    """Collection of policy rules."""
    rules: List[PolicyRule] = Field(
        ...,
        description="List of policy rules"
    )
    metadata: Optional[Dict[str, Any]] = Field(
        None,
        description="Metadata about the rule set"
    )

    def get_rule_by_id(self, rule_id: str) -> Optional[PolicyRule]:
        """Retrieve a rule by ID."""
        for rule in self.rules:
            if rule.rule_id == rule_id:
                return rule
        return None

    def get_enabled_rules(self) -> List[PolicyRule]:
        """Get only enabled rules."""
        return [rule for rule in self.rules if rule.enabled]

    def filter_by_severity(self, severity: Severity) -> List[PolicyRule]:
        """Filter rules by severity level."""
        return [rule for rule in self.rules if rule.severity == severity]