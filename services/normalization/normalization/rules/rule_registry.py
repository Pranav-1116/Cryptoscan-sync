"""
Rule registry — in-memory registry of loaded and validated
normalization rules. Thread-safe for concurrent access.
"""

from __future__ import annotations

import logging
import threading
from typing import Iterator, Optional

from normalization.models.normalization_rule import NormalizationRule

logger = logging.getLogger(__name__)


class DuplicateRuleError(Exception):
    """Raised when a rule_id is registered more than once."""


class RuleRegistry:
    """
    Thread-safe in-memory registry of normalization rules.

    Rules are indexed by:
      - rule_id (unique)
      - each raw_pattern (for O(1) exact-match lookup)

    Usage::

        registry = RuleRegistry()
        registry.register(rule)
        rule = registry.lookup_by_pattern("DES")
        all_rules = list(registry.all_rules())
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # rule_id -> NormalizationRule
        self._rules_by_id: dict[str, NormalizationRule] = {}
        # raw_pattern (uppercase) -> NormalizationRule
        self._rules_by_pattern: dict[str, NormalizationRule] = {}

    # ── Registration ─────────────────────────────────────────────────

    def register(self, rule: NormalizationRule, *, overwrite: bool = False) -> None:
        """
        Register a single normalization rule.

        Args:
            rule: Validated NormalizationRule to register.
            overwrite: If True, silently overwrite duplicate rule_id
                       and pattern conflicts.

        Raises:
            DuplicateRuleError: If rule_id or any pattern already
                                registered and overwrite=False.
        """
        with self._lock:
            if rule.rule_id in self._rules_by_id and not overwrite:
                raise DuplicateRuleError(
                    f"Rule '{rule.rule_id}' is already registered. "
                    "Use overwrite=True to replace it."
                )

            for pattern in rule.raw_patterns:
                key = pattern.upper()
                existing = self._rules_by_pattern.get(key)
                if existing and existing.rule_id != rule.rule_id and not overwrite:
                    raise DuplicateRuleError(
                        f"Pattern '{pattern}' is already mapped to rule "
                        f"'{existing.rule_id}'. Cannot register rule '{rule.rule_id}'."
                    )

            # Commit registration
            self._rules_by_id[rule.rule_id] = rule
            for pattern in rule.raw_patterns:
                self._rules_by_pattern[pattern.upper()] = rule

            logger.debug(
                "Rule registered",
                extra={
                    "rule_id": rule.rule_id,
                    "patterns": rule.raw_patterns,
                },
            )

    def register_all(
        self,
        rules: list[NormalizationRule],
        *,
        overwrite: bool = False,
    ) -> None:
        """Register multiple rules. Atomic: all succeed or none registered."""
        with self._lock:
            # Validate all before registering any
            for rule in rules:
                self.register(rule, overwrite=overwrite)

    # ── Lookup ───────────────────────────────────────────────────────

    def lookup_by_pattern(self, raw_algorithm: str) -> Optional[NormalizationRule]:
        """
        Look up a rule by exact raw pattern match (case-insensitive).

        Args:
            raw_algorithm: Raw algorithm string from scanner (e.g., "DES").

        Returns:
            Matching NormalizationRule or None.
        """
        with self._lock:
            return self._rules_by_pattern.get(raw_algorithm.upper())

    def lookup_by_id(self, rule_id: str) -> Optional[NormalizationRule]:
        """Return rule by rule_id or None."""
        with self._lock:
            return self._rules_by_id.get(rule_id)

    def has_pattern(self, raw_algorithm: str) -> bool:
        """Return True if pattern is registered."""
        with self._lock:
            return raw_algorithm.upper() in self._rules_by_pattern

    # ── Introspection ────────────────────────────────────────────────

    def all_rules(self) -> Iterator[NormalizationRule]:
        """Yield all registered rules (snapshot, thread-safe)."""
        with self._lock:
            yield from list(self._rules_by_id.values())

    def all_patterns(self) -> list[str]:
        """Return sorted list of all registered patterns."""
        with self._lock:
            return sorted(self._rules_by_pattern.keys())

    def rule_count(self) -> int:
        """Return number of registered rules."""
        with self._lock:
            return len(self._rules_by_id)

    def pattern_count(self) -> int:
        """Return number of registered pattern mappings."""
        with self._lock:
            return len(self._rules_by_pattern)

    def clear(self) -> None:
        """Remove all registered rules (useful for testing)."""
        with self._lock:
            self._rules_by_id.clear()
            self._rules_by_pattern.clear()
            logger.debug("Rule registry cleared")

    def stats(self) -> dict:
        """Return registry statistics."""
        with self._lock:
            return {
                "rule_count": len(self._rules_by_id),
                "pattern_count": len(self._rules_by_pattern),
                "rule_ids": sorted(self._rules_by_id.keys()),
            }

    def __repr__(self) -> str:
        return (
            f"RuleRegistry("
            f"rules={self.rule_count()}, "
            f"patterns={self.pattern_count()})"
        )