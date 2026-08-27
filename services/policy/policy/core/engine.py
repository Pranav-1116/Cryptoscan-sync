"""
Policy Engine - Main orchestrator for policy evaluation.

Loads rules from YAML, manages evaluators, and provides public API.
"""

from typing import Any, Dict, Optional, List
import hashlib
import json
import logging
from pathlib import Path

from policy.models.policy_rule import PolicyRule, PolicyRuleSet
from policy.models.policy_result import PolicyEvaluation
from policy.core.evaluator import PolicyEvaluator
from policy.rules.rule_loader import RuleLoader
from policy.rules.rule_validator import RuleValidator

logger = logging.getLogger(__name__)


class PolicyEngine:
    """
    Central policy engine that manages all cryptographic policy evaluation.
    
    This is the main entry point for evaluating findings against policies.
    """

    def __init__(self, rules_directory: str, version: str = "1.0"):
        """
        Initialize the policy engine.
        
        Args:
            rules_directory: Path to directory containing YAML rule files
            version: Policy engine version
        
        Raises:
            FileNotFoundError: If rules directory doesn't exist
            ValueError: If no valid rules found
        """
        self.rules_directory = Path(rules_directory)
        self.version = version
        
        if not self.rules_directory.exists():
            raise FileNotFoundError(
                f"Rules directory not found: {self.rules_directory}"
            )
        
        logger.info(
            f"Initializing PolicyEngine",
            extra={
                "rules_directory": str(self.rules_directory),
                "version": version
            }
        )
        
        # Load and validate rules
        self.rule_set = self._load_rules()
        
        # Create evaluator
        self.evaluator = PolicyEvaluator(self.rule_set, version)
        
        logger.info(
            "PolicyEngine initialized successfully",
            extra={
                "total_rules": len(self.rule_set.rules),
                "enabled_rules": len(self.evaluator.enabled_rules)
            }
        )

    def _load_rules(self) -> PolicyRuleSet:
        """
        Load and validate all rules from YAML files.
        
        Returns:
            PolicyRuleSet with loaded rules
        
        Raises:
            ValueError: If rules are invalid
        """
        loader = RuleLoader(self.rules_directory)
        validator = RuleValidator()
        
        rules = loader.load_all_rules()
        logger.info(f"Loaded {len(rules)} rules from YAML")
        
        # Validate all rules
        for rule in rules:
            validator.validate(rule)
        
        logger.info("All rules validated successfully")
        
        return PolicyRuleSet(rules=rules)

    def evaluate(self, evidence_data: Dict[str, Any]) -> PolicyEvaluation:
        """
        Evaluate evidence against all policies.
        
        Args:
            evidence_data: Dictionary containing cryptographic finding data
        
        Returns:
            PolicyEvaluation with compliance assessment
        """
        return self.evaluator.evaluate(evidence_data)

    def evaluate_batch(
        self,
        evidence_list: List[Dict[str, Any]]
    ) -> List[PolicyEvaluation]:
        """
        Evaluate multiple findings.
        
        Args:
            evidence_list: List of evidence dictionaries
        
        Returns:
            List of PolicyEvaluation results
        """
        results = []
        for evidence in evidence_list:
            try:
                result = self.evaluate(evidence)
                results.append(result)
            except Exception as e:
                logger.error(
                    f"Failed to evaluate evidence item",
                    extra={"error": str(e)},
                    exc_info=True
                )
        
        return results

    def reload_rules(self) -> None:
        """Reload rules from disk (for hot reload during updates)."""
        logger.info("Reloading policy rules from disk")
        new_rule_set = self._load_rules()
        self.rule_set = new_rule_set
        self.evaluator.reload_rules(new_rule_set)
        logger.info("Rules reloaded successfully")

    def get_rule(self, rule_id: str) -> Optional[PolicyRule]:
        """Retrieve a specific rule by ID."""
        return self.rule_set.get_rule_by_id(rule_id)

    def get_enabled_rules(self) -> List[PolicyRule]:
        """Get all enabled rules."""
        return self.evaluator.enabled_rules

    def get_rule_count(self) -> Dict[str, int]:
        """Get counts of rules by status."""
        return {
            "total": len(self.rule_set.rules),
            "enabled": len(self.evaluator.enabled_rules),
            "disabled": len(self.rule_set.rules) - len(self.evaluator.enabled_rules)
        }

    def pack_hash(self) -> str:
        """Stable SHA-256 of the enabled rule pack (id, version, condition, standard)."""
        payload = []
        for rule in sorted(self.rule_set.rules, key=lambda item: item.rule_id):
            payload.append(
                {
                    "rule_id": rule.rule_id,
                    "version": getattr(rule, "version", "1.0"),
                    "enabled": bool(rule.enabled),
                    "severity": rule.severity,
                    "condition_type": rule.condition.type,
                    "standard_reference": rule.standard_reference,
                }
            )
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()

    def pack_descriptor(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "pack_hash": self.pack_hash(),
            "rule_ids": sorted(rule.rule_id for rule in self.rule_set.rules if rule.enabled),
            "counts": self.get_rule_count(),
        }