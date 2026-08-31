"""Exact string matcher."""

from __future__ import annotations

from typing import Optional

from normalization.models.normalization_rule import NormalizationRule


class ExactMatcher:
    def __init__(self, rules):
        self._registry = None
        if hasattr(rules, "lookup_by_pattern"):
            self._registry = rules
            self.rule_map = {}
        else:
            if hasattr(rules, "all_rules"):
                rules = list(rules.all_rules())
            self.rule_map = {}
            for rule in rules:
                patterns = list(getattr(rule, "raw_patterns", None) or [])
                if getattr(rule, "pattern", None):
                    patterns.append(rule.pattern)
                for pattern in patterns:
                    if pattern:
                        self.rule_map[str(pattern).strip().upper()] = rule

    def match(self, raw_algorithm: str) -> Optional[NormalizationRule]:
        if not raw_algorithm or not str(raw_algorithm).strip():
            return None
        key = str(raw_algorithm).strip()
        if self._registry is not None:
            return self._registry.lookup_by_pattern(key)
        return self.rule_map.get(key.upper())
