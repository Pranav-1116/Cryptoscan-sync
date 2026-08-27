"""
PolicyResult and PolicyEvaluation models — output of policy engine.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal, Optional

from pydantic import BaseModel, Field, computed_field


EvaluationResultType = Literal["PASS", "FAIL", "WARN", "NOT_APPLICABLE"]


class PolicyResult(BaseModel):
    """
    Result of evaluating a single policy rule against one evidence record.
    """

    rule_id: str = Field(..., description="Rule that was evaluated")
    rule_name: str = Field(..., description="Human-readable rule name")
    rule_version: str = Field(..., description="Rule version")
    evaluation_result: EvaluationResultType = Field(
        ...,
        description="Outcome: PASS, FAIL, WARN, or NOT_APPLICABLE",
    )
    severity: str = Field(
        ...,
        description="Rule severity (only relevant when FAIL/WARN)",
    )
    message: str = Field(
        ...,
        description="Human-readable evaluation message",
    )
    remediation: Optional[str] = Field(
        None,
        description="Remediation guidance (populated when FAIL/WARN)",
    )
    evaluated_at: str = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc).isoformat(),
        description="ISO-8601 timestamp of evaluation",
    )
    evaluated_by: str = Field(
        default="policy-engine-v1.0",
        description="Component that performed evaluation",
    )
    evidence_used: list[str] = Field(
        default_factory=list,
        description="evidence_id(s) used as input for this evaluation",
    )
    determination_method: str = Field(
        default="deterministic-rule-eval",
        description="Must always be 'deterministic-rule-eval' — not AI",
    )

    @computed_field
    @property
    def is_failure(self) -> bool:
        """Return True if evaluation resulted in FAIL."""
        return self.evaluation_result == "FAIL"

    @computed_field
    @property
    def is_warning(self) -> bool:
        """Return True if evaluation resulted in WARN."""
        return self.evaluation_result == "WARN"


class PolicyEvaluation(BaseModel):
    """
    Aggregated policy evaluation result for one evidence record.
    Contains results from all applicable rules.
    """

    evidence_id: str = Field(..., description="Evidence record being evaluated")
    overall_status: EvaluationResultType = Field(
        ...,
        description="Worst outcome across all rule evaluations",
    )
    rules_evaluated: list[PolicyResult] = Field(
        default_factory=list,
        description="All rule evaluation results",
    )
    evaluation_timestamp: str = Field(
        default_factory=lambda: datetime.now(tz=timezone.utc).isoformat(),
    )
    policy_version: str = Field(
        default="1.0",
        description="Policy rule set version applied",
    )
    total_rules_checked: int = Field(default=0, ge=0)
    rules_failed: int = Field(default=0, ge=0)
    rules_warned: int = Field(default=0, ge=0)
    rules_passed: int = Field(default=0, ge=0)
    rules_skipped: int = Field(default=0, ge=0)
    has_critical_failure: bool = Field(
        default=False,
        description="True when any FAIL result has CRITICAL severity (CRITICAL_FAIL).",
    )

    @classmethod
    def build(
        cls,
        evidence_id: str,
        results: list[PolicyResult],
        *,
        policy_version: str = "1.0",
    ) -> "PolicyEvaluation":
        """
        Build a PolicyEvaluation from a list of individual rule results.
        Automatically determines overall_status.
        """
        failed = [r for r in results if r.is_failure]
        warned = [r for r in results if r.is_warning]
        passed = [r for r in results if r.evaluation_result == "PASS"]
        skipped = [r for r in results if r.evaluation_result == "NOT_APPLICABLE"]

        if failed:
            overall = "FAIL"
        elif warned:
            overall = "WARN"
        elif passed:
            overall = "PASS"
        else:
            overall = "NOT_APPLICABLE"

        return cls(
            evidence_id=evidence_id,
            overall_status=overall,
            rules_evaluated=results,
            policy_version=policy_version,
            total_rules_checked=len(results),
            rules_failed=len(failed),
            rules_warned=len(warned),
            rules_passed=len(passed),
            rules_skipped=len(skipped),
            has_critical_failure=any(
                "CRITICAL" in str(getattr(item.severity, "value", item.severity)).upper() for item in failed
            ),
        )

    def failed_rule_ids(self) -> list[str]:
        """Return rule_ids of all FAIL results."""
        return [r.rule_id for r in self.rules_evaluated if r.is_failure]

    def critical_failures(self) -> list[PolicyResult]:
        """Return FAIL results with CRITICAL severity."""
        return [
            r for r in self.rules_evaluated
            if r.is_failure and r.severity == "CRITICAL"
        ]

    def to_db_jsonb(self) -> dict:
        """Serialize to JSONB-compatible dict for storage in evidence_records."""
        return self.model_dump(mode="json")