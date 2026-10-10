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
from normalization.enrichers.quantum_enricher import QuantumEnricher
from normalization.enrichers.iana_enricher import IanaEnricher
from normalization.enrichers.nist_enricher import NistEnricher
from normalization.matchers.exact_matcher import ExactMatcher
from normalization.matchers.alias_canonicalizer import canonicalize
from normalization.matchers.fallback_handler import FallbackHandler
from normalization.matchers.pattern_matcher import PatternMatcher
from normalization.core.registry_bridge import resolve_key_size
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
        self._quantum_enricher = QuantumEnricher()

    def process(
        self,
        raw_algorithm: str,
        *,
        purpose: Optional[str] = None,
        key_size: Optional[int] = None,
        mode: Optional[str] = None,
        padding: Optional[str] = None,
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
            mode: Optional mode of operation hint (e.g., "GCM").
            padding: Optional padding scheme hint from scanner context.
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

        # ── Step 1b: Alias rescue (report 53's collision catalogue) ────
        # Only consulted when the raw string did not exact-match, so every
        # working path is untouched: AES256/AES_256 -> AES-256,
        # secp256r1/prime256v1 -> P-256, HMACSHA256 -> HMAC-SHA256,
        # lowercase spellings retried uppercased. The string that produced
        # the match (raw or canonical) drives pattern matching and key-size
        # extraction downstream.
        match_input = raw_stripped
        if matched_rule is None:
            canonical = canonicalize(raw_stripped)
            if canonical != raw_stripped:
                match_input = canonical
                aliased_hit = self._exact_matcher.match(canonical)
                if isinstance(aliased_hit, NormalizationRule):
                    matched_rule = aliased_hit
                    confidence = "HIGH"
                    parse_mode = "exact-alias"

        # ── Step 2: Pattern match (compound strings) ──────────────────
        pattern_hit = None
        if matched_rule is None:
            pattern_hit = self._pattern_matcher.match(match_input)
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
            if mode and not result.mode:
                result.mode = str(mode).upper()
            if padding and not result.padding:
                result.padding = padding
            logger.warning(
                "Algorithm could not be normalized, flagged for review: '%s'",
                raw_stripped,
            )
            return result

        # ── Step 4: Build base NormalizedCrypto from rule or pattern ──
        if isinstance(pattern_hit, NormalizedCrypto) and matched_rule is None:
            normalized = pattern_hit
            normalized.key_size = resolve_key_size(
                normalized.key_size, match_input, key_size
            )
            if mode is not None and not normalized.mode:
                normalized.mode = str(mode).upper()
            if padding is not None and not normalized.padding:
                normalized.padding = padding
            if purpose is not None and normalized.purpose is None:
                normalized.purpose = purpose
            normalized.raw_input = raw_stripped
            normalized.normalization_confidence = confidence
            normalized.normalization_version = normalization_version
            normalized.normalization_timestamp = timestamp
        else:
            output = matched_rule.normalized_output.copy()
            output["key_size"] = resolve_key_size(
                output.get("key_size"), match_input, key_size
            )
            if mode is not None and not output.get("mode"):
                output["mode"] = str(mode).upper()
            if padding is not None and not output.get("padding"):
                output["padding"] = padding
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
        normalized = self._quantum_enricher.enrich(normalized)

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