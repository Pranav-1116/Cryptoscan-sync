"""Normalization engine."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from normalization.enrichers.cbom_enricher import CBOMEnricher
from normalization.enrichers.family_enricher import FamilyEnricher
from normalization.enrichers.iana_enricher import IANAEnricher
from normalization.enrichers.nist_enricher import NISTEnricher
from normalization.matchers.exact_matcher import ExactMatcher
from normalization.matchers.fallback_handler import FallbackHandler
from normalization.matchers.pattern_matcher import PatternMatcher
from normalization.models.normalized_crypto import NormalizedCrypto
from normalization.rules.rule_loader import RuleLoader

logger = logging.getLogger(__name__)


class NormalizationEngine:
    def __init__(self, rules_directory: str):
        self.rule_loader = RuleLoader(rules_directory)
        self.rules = self.rule_loader.load_all_rules()
        self.exact_matcher = ExactMatcher(self.rules)
        self.pattern_matcher = PatternMatcher()
        self.fallback_handler = FallbackHandler()
        self.nist_enricher = NISTEnricher()
        self.iana_enricher = IANAEnricher()
        self.cbom_enricher = CBOMEnricher()
        self.family_enricher = FamilyEnricher()
        logger.info("normalization_engine_ready", extra={"rules": len(self.rules)})

    def normalize(self, raw_algorithm: str, context: dict[str, Any] | None = None) -> NormalizedCrypto:
        context = context or {}
        raw = (raw_algorithm or "UNKNOWN").strip()
        confidence = "LOW"
        normalized = None

        if raw and raw.upper() != "UNKNOWN":
            normalized = self._from_rule(self.exact_matcher.match(raw), raw)
            if normalized:
                confidence = "HIGH"
            else:
                pattern = self.pattern_matcher.match(raw)
                normalized = self._from_rule(pattern, raw) if pattern else None
                if normalized:
                    confidence = "MEDIUM"

        if normalized is None:
            try:
                normalized = self.fallback_handler.handle_unknown(raw, context)
            except Exception:
                normalized = self._unknown(raw, context)
            confidence = "LOW"

        if context.get("mode") and not normalized.mode:
            normalized.mode = context["mode"]
        if context.get("key_size") and not normalized.key_size:
            normalized.key_size = context["key_size"]
        if context.get("padding") and not normalized.padding:
            normalized.padding = context["padding"]
        if context.get("purpose") and not normalized.purpose:
            normalized.purpose = str(context["purpose"]).lower()

        try:
            normalized = self.nist_enricher.enrich(normalized)
        except Exception:
            pass
        try:
            normalized = self.iana_enricher.enrich(normalized)
        except Exception:
            pass
        try:
            normalized = self.cbom_enricher.enrich(normalized)
        except Exception:
            pass
        try:
            normalized = self.family_enricher.enrich(normalized)
        except Exception:
            pass

        normalized.normalization_confidence = confidence
        normalized.normalization_version = "1.0"
        normalized.raw_input = raw
        normalized.normalization_timestamp = datetime.now(timezone.utc).isoformat()
        return normalized

    def normalize_batch(self, evidence_records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        for record in evidence_records:
            finding = record.get("finding") or record.get("finding_data") or {}
            crypto = finding.get("crypto") or {}
            raw = crypto.get("algorithm") or record.get("algorithm") or "UNKNOWN"
            normalized = self.normalize(
                raw,
                context={
                    "mode": crypto.get("mode") or record.get("mode"),
                    "key_size": crypto.get("key_size") or record.get("key_size"),
                    "padding": crypto.get("padding") or record.get("padding"),
                    "purpose": crypto.get("purpose") or record.get("purpose"),
                },
            )
            record["normalized_crypto"] = normalized.model_dump(mode="json")
        return evidence_records

    def _from_rule(self, matched: Any, raw: str) -> NormalizedCrypto | None:
        if matched is None:
            return None
        if isinstance(matched, NormalizedCrypto):
            matched.raw_input = raw
            return matched
        output = getattr(matched, "output", None) or getattr(matched, "normalized_output", None)
        if isinstance(matched, dict):
            output = matched.get("output") or matched.get("normalized_output") or matched
        if not output:
            return None
        return self._build(output, raw, "HIGH")

    def _build(self, output: dict[str, Any], raw: str, confidence: str) -> NormalizedCrypto:
        payload = {
            "algorithm": output.get("algorithm", "UNKNOWN"),
            "algorithm_family": output.get("algorithm_family", "unknown"),
            "standard_name": output.get("standard_name") or output.get("algorithm") or raw,
            "mode": output.get("mode"),
            "padding": output.get("padding"),
            "key_size": output.get("key_size"),
            "iv_size": output.get("iv_size"),
            "tag_size": output.get("tag_size"),
            "output_bits": output.get("output_bits"),
            "purpose": output.get("purpose"),
            "iana_id": output.get("iana_id"),
            "nist_designation": output.get("nist_designation"),
            "nist_reference": output.get("nist_reference"),
            "fips_status": output.get("fips_status"),
            "quantum_vulnerable": bool(output.get("quantum_vulnerable", False)),
            "pqc_replacement": output.get("pqc_replacement"),
            "cbom_component_type": output.get("cbom_component_type", "cryptographic-asset"),
            "cbom_algorithm_ref": output.get("cbom_algorithm_ref"),
            "normalization_confidence": confidence,
            "raw_input": raw,
            "needs_human_review": output.get("algorithm") in {None, "UNKNOWN"},
        }
        return NormalizedCrypto(**payload)

    def _unknown(self, raw: str, context: dict[str, Any]) -> NormalizedCrypto:
        return NormalizedCrypto(
            algorithm=raw or "UNKNOWN",
            algorithm_family="unknown",
            standard_name=raw or "UNKNOWN",
            mode=context.get("mode"),
            key_size=context.get("key_size"),
            purpose=context.get("purpose"),
            nist_designation="UNKNOWN",
            normalization_confidence="LOW",
            raw_input=raw,
            needs_human_review=True,
            review_reason="No normalization rule matched",
        )
