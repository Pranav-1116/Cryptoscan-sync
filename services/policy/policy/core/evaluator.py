"""Evaluate one finding against all enabled rules."""

from __future__ import annotations

import logging
from typing import Any

from policy.conditions.condition_factory import ConditionFactory
from policy.models.policy_result import PolicyEvaluation, PolicyResult
from policy.models.policy_rule import PolicyRuleSet

logger = logging.getLogger(__name__)


class PolicyEvaluator:
    def __init__(self, rule_set: PolicyRuleSet, engine_version: str = "1.0"):
        self.rule_set = rule_set
        self.engine_version = engine_version
        self.enabled_rules = rule_set.get_enabled_rules()
        self.factory = ConditionFactory()

    def evaluate(self, evidence_data: dict[str, Any]) -> PolicyEvaluation:
        results: list[PolicyResult] = []
        for rule in self.enabled_rules:
            condition_type = rule.condition.type
            if hasattr(condition_type, "value"):
                condition_type = condition_type.value
            try:
                condition = self.factory.create(str(condition_type))
                outcome = condition.safe_evaluate(evidence_data, rule.condition.parameters)
                result_value = outcome.result
                message = outcome.message
            except Exception as exc:
                logger.exception("rule_eval_failed", extra={"rule_id": rule.rule_id})
                result_value = "WARN"
                message = f"Error evaluating rule: {exc}"

            results.append(
                PolicyResult(
                    rule_id=rule.rule_id,
                    rule_name=rule.rule_name,
                    rule_version=rule.version,
                    evaluation_result=result_value,  # type: ignore[arg-type]
                    severity=str(rule.severity),
                    message=message,
                    remediation=rule.remediation if result_value == "FAIL" else None,
                    evaluated_by=f"policy-engine-v{self.engine_version}",
                    evidence_used=[str(evidence_data.get("id") or evidence_data.get("evidence_id") or "")],
                )
            )

        evidence_id = str(evidence_data.get("id") or evidence_data.get("evidence_id") or "unknown")
        evaluation = PolicyEvaluation.build(
            evidence_id=evidence_id,
            results=results,
            policy_version=self.engine_version,
        )
        return evaluation

    def reload_rules(self, rule_set: PolicyRuleSet) -> None:
        self.rule_set = rule_set
        self.enabled_rules = rule_set.get_enabled_rules()
