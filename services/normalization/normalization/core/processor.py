"""
Normalization processor — processes a single evidence record through
the full normalization pipeline: match → enrich → store.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from normalization.enrichers.cbom_enricher import CbomEnricher
from normalization.enrichers.family_enricher import FamilyEnricher
from normalization.enrichers.iana_enricher import IanaEnricher
from normalization.enrichers.nist_enricher import NistEnricher
from normalization.matchers.exact_matcher import ExactMatcher
from normalization.matchers.fallback_handler import FallbackHandler
from normalization.matchers.pattern_matcher import PatternMatcher
from normalization.models.normalization_rule import NormalizationRule
from normalization.models.normalized_crypto import NormalizedCrypto
from normalization.rules.rule_registry import RuleRegistry

logger = logging.getLogger(__name__)


class NormalizationProcessor:
    """
    Processes a single raw algorithm string through the full
    normalization pipeline.

    Pipeline:
      1. ExactMatcher   — O(1) lookup against rule registry
      2. PatternMatcher — parse "algo/mode/padding" compound strings
      3. FallbackHandler — mark as UNKNOWN + flag for human review
      4. Enrichers       — add NIST, IANA, CBOM, family metadata
    """

    def __init__(self, registry: RuleRegistry) -> None:
        self._registry = registry
        self._exact_matcher = ExactMatcher(registry)
        self._pattern_matcher = PatternMatcher(registry)
        self._fallback_handler = FallbackHandler()
        self._nist_enricher = NistEnricher()
        self._iana_enricher = IanaEnricher()
        self._cbom_enricher = CbomEnricher()
        self._family_enricher = FamilyEnricher()

    def process(
        self,
        raw_algorithm: str,
        *,
        purpose: Optional[str] = None,
        key_size: Optional[int] = None,
        normalization_version: str = "1.0",
    ) -> NormalizedCrypto:
        """
        Normalize a raw algorithm string to canonical form.

        Args:
            raw_algorithm: Raw algorithm string from scanner
                           (e.g., "AES/GCM/NoPadding", "SHA256withRSA").
            purpose: Optional cryptographic purpose hint from scanner
                     (e.g., "encryption", "hashing").
            key_size: Optional key size in bits from scanner context.
            normalization_version: Version of normalization rules applied.

        Returns:
            NormalizedCrypto with all fields populated.
        """
        timestamp = datetime.now(tz=timezone.utc).isoformat()
        raw_stripped = raw_algorithm.strip()

        logger.debug("Normalizing algorithm: '%s'", raw_stripped)

        # ── Step 1: Exact match ───────────────────────────────────────
        matched_rule: Optional[NormalizationRule] = self._exact_matcher.match(raw_stripped)
        confidence = "HIGH"
        parse_mode: str = "exact"

        # ── Step 2: Pattern match (compound strings) ──────────────────
        pattern_hit = None
        if matched_rule is None:
            pattern_hit = self._pattern_matcher.match(raw_stripped)
            if isinstance(pattern_hit, NormalizationRule):
                matched_rule = pattern_hit
                confidence = "MEDIUM"
                parse_mode = "pattern"
            elif isinstance(pattern_hit, NormalizedCrypto):
                confidence = "MEDIUM"
                parse_mode = "pattern"

        # ── Step 3: Fallback ──────────────────────────────────────────
        if matched_rule is None and not isinstance(pattern_hit, NormalizedCrypto):
            result = self._fallback_handler.handle(
                raw_algorithm=raw_stripped,
                purpose=purpose,
                key_size=key_size,
                normalization_version=normalization_version,
                timestamp=timestamp,
            )
            logger.warning(
                "Algorithm could not be normalized, flagged for review: '%s'",
                raw_stripped,
            )
            return result

        # ── Step 4: Build base NormalizedCrypto from rule or pattern ──
        if isinstance(pattern_hit, NormalizedCrypto) and matched_rule is None:
            normalized = pattern_hit
            if key_size is not None and normalized.key_size is None:
                normalized.key_size = key_size
            if purpose is not None and normalized.purpose is None:
                normalized.purpose = purpose
            normalized.raw_input = raw_stripped
            normalized.normalization_confidence = confidence
            normalized.normalization_version = normalization_version
            normalized.normalization_timestamp = timestamp
        else:
            output = matched_rule.normalized_output.copy()
            if key_size is not None and output.get("key_size") is None:
                output["key_size"] = key_size
            if purpose is not None and output.get("purpose") is None:
                output["purpose"] = purpose
            output["raw_input"] = raw_stripped
            output["normalization_confidence"] = confidence
            output["normalization_version"] = normalization_version
            output["normalization_timestamp"] = timestamp
            output["needs_human_review"] = False
            output["review_reason"] = None
            try:
                normalized = NormalizedCrypto.model_validate(output)
            except Exception as exc:
                logger.error(
                    "NormalizedCrypto model validation failed for '%s': %s",
                    raw_stripped,
                    exc,
                )
                return self._fallback_handler.handle(
                    raw_algorithm=raw_stripped,
                    purpose=purpose,
                    key_size=key_size,
                    normalization_version=normalization_version,
                    timestamp=timestamp,
                )

        # ── Step 5: Apply enrichers (do not clobber rule values) ──────
        normalized = self._nist_enricher.enrich(normalized)
        normalized = self._iana_enricher.enrich(normalized)
        normalized = self._cbom_enricher.enrich(normalized)
        normalized = self._family_enricher.enrich(normalized)

        logger.debug(
            "Normalization complete",
            extra={
                "raw": raw_stripped,
                "normalized": normalized.standard_name,
                "confidence": confidence,
                "parse_mode": parse_mode,
                "nist": normalized.nist_designation,
            },
        )
        return normalized