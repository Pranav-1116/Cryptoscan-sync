"""
Policy Evaluator - Evaluates findings against policy rules.

Core logic that applies rules to individual findings and produces results.
"""

from typing import Any, Dict, List
import logging
from datetime import datetime
from policy.models.policy_rule import PolicyRule, PolicyRuleSet
from policy.models.policy_result import PolicyResult, PolicyEvaluation
from policy.conditions.condition_factory import ConditionFactory

logger = logging.getLogger(__name__)


class PolicyEvaluator:
    """Evaluates cryptographic findings against policy rules."""

    def __init__(self, rule_set: PolicyRuleSet, engine_version: str = "1.0"):
        """
        Initialize evaluator with a rule set.
        
        Args:
            rule_set: PolicyRuleSet containing rules to apply
            engine_version: Version of the policy engine
        """
        self.rule_set = rule_set
        self.engine_version = engine_version
        self.enabled_rules = rule_set.get_enabled_rules()
        
        logger.info(
            f"Policy evaluator initialized",
            extra={
                "total_rules": len(rule_set.rules),
                "enabled_rules": len(self.enabled_rules),
                "engine_version": engine_version
            }
        )

    def evaluate(self, evidence_data: Dict[str, Any]) -> PolicyEvaluation:
        """
        Evaluate evidence against all applicable rules.
        
        Args:
            evidence_data: Dictionary containing finding/evidence data
                          Should include: algorithm, key_size, mode, purpose,
                          file_path, line_number, is_hardcoded_key, etc.
        
        Returns:
            PolicyEvaluation with results for all applicable rules
        """
        logger.debug(
            "Evaluating evidence against policy rules",
            extra={
                "evidence_keys": list(evidence_data.keys()),
                "algorithm": evidence_data.get("algorithm")
            }
        )
        
        # Evaluate each enabled rule
        policy_results: List[PolicyResult] = []
        
        for rule in self.enabled_rules:
            result = self._evaluate_rule(rule, evidence_data)
            policy_results.append(result)
        
        # Determine overall status
        overall_status = self._determine_overall_status(policy_results)
        
        # Create aggregated evaluation
        evaluation = PolicyEvaluation(
            overall_status=overall_status,
            rules_evaluated=policy_results,
            policy_version=self.engine_version,
            compliance_status=overall_status
        )
        
        logger.info(
            "Policy evaluation completed",
            extra={
                "algorithm": evidence_data.get("algorithm"),
                "overall_status": overall_status,
                "total_rules": len(policy_results),
                "failed": evaluation.failure_count(),
                "warned": evaluation.warning_count()
            }
        )
        
        return evaluation

    def _evaluate_rule(
        self,
        rule: PolicyRule,
        evidence_data: Dict[str, Any]
    ) -> PolicyResult:
        """
        Evaluate a single rule against evidence.
        
        Args:
            rule: The rule to evaluate
            evidence_data: Evidence to test against
        
        Returns:
            PolicyResult with outcome
        """
        logger.debug(
            f"Evaluating rule {rule.rule_id}",
            extra={"algorithm": evidence_data.get("algorithm")}
        )
        
        try:
            # Create condition evaluator
            condition = ConditionFactory.create(
                rule.condition.type,
                rule.condition.parameters
            )
            
            # Evaluate condition
            evaluation_result, message = condition.evaluate(evidence_data)
            
        except Exception as e:
            logger.error(
                f"Error evaluating rule {rule.rule_id}",
                extra={"error": str(e)},
                exc_info=True
            )
            evaluation_result = "WARN"
            message = f"Error evaluating rule: {str(e)}"
        
        # Get remediation if failed
        remediation = None
        if evaluation_result == "FAIL":
            remediation = rule.remediation
        
        # Create result object
        result = PolicyResult(
            rule_id=rule.rule_id,
            rule_name=rule.rule_name,
            rule_version=rule.version,
            evaluation_result=evaluation_result,
            severity=rule.severity.value,
            message=message,
            remediation=remediation,
            evaluated_by=f"policy-engine-v{self.engine_version}",
            evidence_used=[],  # Could populate if tracking evidence IDs
            determination_method="deterministic-rule-eval"
        )
        
        logger.debug(
            f"Rule {rule.rule_id} evaluation: {evaluation_result}",
            extra={"message": message}
        )
        
        return result

    def _determine_overall_status(
        self,
        results: List[PolicyResult]
    ) -> str:
        """
        Determine overall compliance status from rule results.
        
        Logic:
        - If any FAIL → FAIL
        - Else if any WARN → WARN
        - Else → PASS
        
        Args:
            results: List of PolicyResult objects
        
        Returns:
            Overall status: "FAIL", "WARN", or "PASS"
        """
        # Check for any failures
        for result in results:
            if result.evaluation_result == "FAIL":
                return "FAIL"
        
        # Check for any warnings
        for result in results:
            if result.evaluation_result == "WARN":
                return "WARN"
        
        # All passed
        return "PASS"

    def reload_rules(self, rule_set: PolicyRuleSet) -> None:
        """
        Reload rules (for hot reload capability).
        
        Args:
            rule_set: New PolicyRuleSet to use
        """
        logger.info(
            f"Reloading policy rules",
            extra={
                "old_rule_count": len(self.enabled_rules),
                "new_rule_count": len(rule_set.get_enabled_rules())
            }
        )
        self.rule_set = rule_set
        self.enabled_rules = rule_set.get_enabled_rules()