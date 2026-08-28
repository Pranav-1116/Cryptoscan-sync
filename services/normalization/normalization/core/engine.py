"""Normalization engine.

Thin facade over :class:`NormalizationProcessor` — previously the two
classes implemented the same pipeline twice with drifting semantics
(different fallback shapes, different key-size precedence, one lowercased
purposes). One core path now serves both entry points.
"""

from __future__ import annotations

import logging
from typing import Any

from normalization.core.processor import NormalizationProcessor
from normalization.enrichers.cbom_enricher import CBOMEnricher
from normalization.enrichers.family_enricher import FamilyEnricher
from normalization.enrichers.iana_enricher import IANAEnricher
from normalization.enrichers.nist_enricher import NISTEnricher
from normalization.matchers.exact_matcher import ExactMatcher
from normalization.matchers.fallback_handler import FallbackHandler
from normalization.matchers.pattern_matcher import PatternMatcher
from normalization.models.normalized_crypto import NormalizedCrypto
from normalization.rules.rule_loader import RuleLoader
from normalization.rules.rule_registry import RuleRegistry

logger = logging.getLogger(__name__)


class NormalizationEngine:
    def __init__(self, rules_directory: str):
        self.rule_loader = RuleLoader(rules_directory)
        self.rules = self.rule_loader.load_all_rules()
        registry = RuleRegistry()
        registry.register_all(self.rules, overwrite=True)
        self.registry = registry
        self.processor = NormalizationProcessor(registry)
        # kept for backward compatibility with existing consumers/tests
        self.exact_matcher = ExactMatcher(registry)
        self.pattern_matcher = PatternMatcher(registry)
        self.fallback_handler = FallbackHandler()
        self.nist_enricher = NISTEnricher()
        self.iana_enricher = IANAEnricher()
        self.cbom_enricher = CBOMEnricher()
        self.family_enricher = FamilyEnricher()
        logger.info("normalization_engine_ready", extra={"rules": len(self.rules)})

    def normalize(self, raw_algorithm: str, context: dict[str, Any] | None = None) -> NormalizedCrypto:
        context = context or {}
        return self.processor.process(
            (raw_algorithm or "UNKNOWN").strip(),
            purpose=context.get("purpose"),
            key_size=context.get("key_size"),
            mode=context.get("mode"),
            padding=context.get("padding"),
        )

    def normalize_batch(self, evidence_records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        for record in evidence_records:
            finding = record.get("finding") or record.get("finding_data") or {}
            crypto = finding.get("crypto") or {}
            normalized = self.normalize(
                crypto.get("algorithm") or record.get("algorithm") or "UNKNOWN",
                context={
                    "mode": crypto.get("mode") or record.get("mode"),
                    "key_size": crypto.get("key_size") or record.get("key_size"),
                    "padding": crypto.get("padding") or record.get("padding"),
                    "purpose": crypto.get("purpose") or record.get("purpose"),
                },
            )
            record["normalized_crypto"] = normalized.model_dump(mode="json")
        return evidence_records
