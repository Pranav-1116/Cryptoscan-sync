"""
Integration tests for the full normalization pipeline.
Tests 20+ algorithm patterns end-to-end through processor.
"""

from __future__ import annotations

import pytest
from pathlib import Path

from normalization.core.engine import NormalizationEngine
from normalization.core.processor import NormalizationProcessor
from normalization.models.normalized_crypto import NormalizedCrypto
from normalization.rules.rule_loader import RuleLoader
from normalization.rules.rule_registry import RuleRegistry


# ── Fixtures ──────────────────────────────────────────────────────────

RULE_DEFINITIONS_DIR = Path(__file__).parent.parent.parent / "rule_definitions"


@pytest.fixture(scope="module")
def loaded_registry() -> RuleRegistry:
    """Registry loaded from real YAML rule definitions."""
    loader = RuleLoader()
    registry = RuleRegistry()
    rules = loader.load_from_directory(RULE_DEFINITIONS_DIR)
    registry.register_all(rules, overwrite=True)
    return registry


@pytest.fixture(scope="module")
def processor(loaded_registry: RuleRegistry) -> NormalizationProcessor:
    return NormalizationProcessor(loaded_registry)


# ── Helper ────────────────────────────────────────────────────────────

def normalize(processor: NormalizationProcessor, raw: str, **kwargs) -> NormalizedCrypto:
    return processor.process(raw, **kwargs)


# ── Tests: Approved Algorithms ────────────────────────────────────────

class TestApprovedAlgorithms:
    """All approved algorithms should normalize to NIST APPROVED."""

    @pytest.mark.parametrize("raw", [
        "AES/GCM/NoPadding",
        "AES-256-GCM",
        "AES256GCM",
    ])
    def test_aes_gcm_256_approved(self, processor: NormalizationProcessor, raw: str) -> None:
        result = normalize(processor, raw)
        assert result.algorithm == "AES"
        assert result.mode == "GCM"
        assert result.nist_designation == "APPROVED"
        assert result.normalization_confidence == "HIGH"
        assert not result.needs_human_review

    def test_sha256_approved(self, processor: NormalizationProcessor) -> None:
        result = normalize(processor, "SHA-256")
        assert result.algorithm == "SHA2"
        assert result.output_bits == 256
        assert result.nist_designation == "APPROVED"
        assert result.algorithm_family == "hash"

    def test_sha512_approved(self, processor: NormalizationProcessor) -> None:
        result = normalize(processor, "SHA-512")
        assert result.algorithm == "SHA2"
        assert result.output_bits == 512
        assert result.nist_designation == "APPROVED"

    def test_sha256_alias(self, processor: NormalizationProcessor) -> None:
        result = normalize(processor, "SHA256")
        assert result.standard_name == "SHA-256"

    def test_rsa_signature_sha256(self, processor: NormalizationProcessor) -> None:
        result = normalize(processor, "SHA256withRSA")
        assert result.algorithm == "RSA"
        assert result.algorithm_family == "signature"
        assert result.purpose == "signing"
        assert result.nist_designation == "APPROVED"


# ── Tests: Disallowed / Deprecated Algorithms ─────────────────────────

class TestForbiddenAlgorithms:
    """Forbidden algorithms should normalize to DISALLOWED."""

    def test_des_disallowed(self, processor: NormalizationProcessor) -> None:
        result = normalize(processor, "DES")
        assert result.algorithm == "DES"
        assert result.key_size == 56
        assert result.nist_designation == "DISALLOWED"
        assert result.quantum_vulnerable is True
        assert result.normalization_confidence == "HIGH"

    def test_des_ecb_disallowed(self, processor: NormalizationProcessor) -> None:
        result = normalize(processor, "DES/ECB/PKCS5Padding")
        assert result.nist_designation == "DISALLOWED"

    @pytest.mark.parametrize("raw", [
        "DESede",
        "DESede/CBC/PKCS5Padding",
        "3DES",
        "TripleDES",
    ])
    def test_3des_disallowed(self, processor: NormalizationProcessor, raw: str) -> None:
        result = normalize(processor, raw)
        assert result.algorithm == "3DES"
        assert result.nist_designation == "DISALLOWED"

    def test_md5_disallowed(self, processor: NormalizationProcessor) -> None:
        result = normalize(processor, "MD5")
        assert result.algorithm == "MD5"
        assert result.nist_designation == "DISALLOWED"
        assert result.output_bits == 128

    @pytest.mark.parametrize("raw", ["SHA-1", "SHA1", "SHA1withRSA"])
    def test_sha1_deprecated(self, processor: NormalizationProcessor, raw: str) -> None:
        result = normalize(processor, raw)
        assert result.nist_designation in {"DEPRECATED", "DISALLOWED"}

    def test_aes_ecb_deprecated(self, processor: NormalizationProcessor) -> None:
        result = normalize(processor, "AES/ECB/PKCS5Padding")
        assert result.mode == "ECB"
        assert result.nist_designation == "DEPRECATED"


# ── Tests: Unknown Algorithms ─────────────────────────────────────────

class TestUnknownAlgorithms:
    """Unknown algorithms should be flagged for human review."""

    def test_custom_crypto_flagged(self, processor: NormalizationProcessor) -> None:
        result = normalize(processor, "CustomCrypto")
        assert result.algorithm == "UNKNOWN"
        assert result.needs_human_review is True
        assert result.review_reason is not None
        assert result.normalization_confidence == "LOW"

    def test_empty_algorithm_flagged(self, processor: NormalizationProcessor) -> None:
        result = normalize(processor, "")
        assert result.needs_human_review is True

    def test_variable_placeholder_flagged(self, processor: NormalizationProcessor) -> None:
        # Scanner emits this when algo comes from a variable
        result = normalize(processor, "UNKNOWN_VARIABLE_ALGO")
        assert result.needs_human_review is True


# ── Tests: Key Size Hint ──────────────────────────────────────────────

class TestKeySizeHints:
    """Scanner-provided key_size hints should be merged into output."""

    def test_key_size_merged_for_generic_rsa(self, processor: NormalizationProcessor) -> None:
        result = normalize(processor, "RSA", key_size=2048)
        assert result.key_size == 2048

    def test_key_size_not_overwritten_when_rule_has_value(
        self, processor: NormalizationProcessor
    ) -> None:
        # DES rule defines key_size=56 — scanner hint should not override
        result = normalize(processor, "DES", key_size=999)
        assert result.key_size == 56


# ── Tests: Normalization Metadata ─────────────────────────────────────

class TestNormalizationMetadata:
    """All results must carry required metadata fields."""

    def test_timestamp_present(self, processor: NormalizationProcessor) -> None:
        result = normalize(processor, "AES/GCM/NoPadding")
        assert result.normalization_timestamp is not None
        assert "T" in result.normalization_timestamp  # ISO-8601

    def test_version_present(self, processor: NormalizationProcessor) -> None:
        result = normalize(processor, "SHA-256")
        assert result.normalization_version == "1.0"

    def test_raw_input_preserved(self, processor: NormalizationProcessor) -> None:
        result = normalize(processor, "DES/ECB/PKCS5Padding")
        assert result.raw_input == "DES/ECB/PKCS5Padding"

    def test_cbom_fields_populated_for_approved(
        self, processor: NormalizationProcessor
    ) -> None:
        result = normalize(processor, "AES/GCM/NoPadding")
        assert result.cbom_component_type == "cryptographic-asset"
        assert result.cbom_algorithm_ref is not None