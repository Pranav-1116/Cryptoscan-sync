"""
Rule Registry - In-memory registry of loaded policy rules.

Provides efficient lookup and filtering of rules.
"""

from typing import List, Optional, Dict
import logging
from policy.models.policy_rule import PolicyRule, Severity

logger = logging.getLogger(__name__)


class RuleRegistry:
    """In-memory registry of policy rules."""

    def __init__(self, rules: List[PolicyRule]):
        """
        Initialize registry with rules.
        
        Args:
            rules: List of PolicyRule objects to register
        """
        self.rules = rules
        self._build_indexes()
        logger.info(f"Initialized rule registry with {len(rules)} rules")

    def _build_indexes(self) -> None:
        """Build lookup indexes for efficient retrieval."""
        self._rules_by_id: Dict[str, PolicyRule] = {}
        self._rules_by_severity: Dict[str, List[PolicyRule]] = {
            s.value: [] for s in Severity
        }

        for rule in self.rules:
            self._rules_by_id[rule.rule_id] = rule
            # PolicyRule.severity is a plain str field; accept enums too so
            # callers that construct with Severity members keep working.
            severity = getattr(rule.severity, "value", None) or str(rule.severity).upper()
            bucket = self._rules_by_severity.setdefault(severity, [])
            bucket.append(rule)

    def get_rule(self, rule_id: str) -> Optional[PolicyRule]:
        """
        Get rule by ID.
        
        Args:
            rule_id: Rule ID to lookup
        
        Returns:
            PolicyRule or None if not found
        """
        return self._rules_by_id.get(rule_id)

    def get_rules_by_severity(self, severity: Severity) -> List[PolicyRule]:
        """
        Get all rules of a specific severity level.
        
        Args:
            severity: Severity level to filter by
        
        Returns:
            List of matching rules
        """
        return self._rules_by_severity.get(severity.value, [])

    def get_enabled_rules(self) -> List[PolicyRule]:
        """Get all enabled rules."""
        return [r for r in self.rules if r.enabled]

    def get_all_rules(self) -> List[PolicyRule]:
        """Get all registered rules."""
        return self.rules.copy()

    def count_rules(self, enabled_only: bool = False) -> int:
        """
        Count rules.
        
        Args:
            enabled_only: If True, count only enabled rules
        
        Returns:
            Number of rules
        """
        if enabled_only:
            return len(self.get_enabled_rules())
        return len(self.rules)

    def validate_registry(self) -> bool:
        """
        Validate registry integrity.
        
        Returns:
            True if valid
        
        Raises:
            ValueError: If registry is invalid
        """
        # Check for duplicate rule IDs
        rule_ids = [r.rule_id for r in self.rules]
        if len(rule_ids) != len(set(rule_ids)):
            duplicates = [
                rid for rid in rule_ids
                if rule_ids.count(rid) > 1
            ]
            raise ValueError(f"Duplicate rule IDs found: {duplicates}")
        
        logger.info("Rule registry validation passed")
        return True