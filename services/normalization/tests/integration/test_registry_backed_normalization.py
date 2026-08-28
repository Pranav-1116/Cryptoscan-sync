"""Engine-level behavior of the registry-backed pipeline (Ask-51)."""

from __future__ import annotations

from normalization.core.engine import NormalizationEngine
from normalization.models.normalized_crypto import NormalizedCrypto


def test_scanner_key_size_beats_rule_default(engine: NormalizationEngine):
    # "AES/GCM/NoPadding" carries no size; the rule guessed 256. A scanner
    # that measured 128 used to be silently recorded as 256.
    result = engine.normalize("AES/GCM/NoPadding", context={"key_size": 128})
    assert result.algorithm == "AES" and result.mode == "GCM"
    assert result.key_size == 128


def test_size_written_in_raw_string_wins(engine: NormalizationEngine):
    result = engine.normalize("AES-256-GCM", context={"key_size": 128})
    assert result.key_size == 256


def test_fixed_key_size_immune_to_bogus_hints(engine: NormalizationEngine):
    result = engine.normalize("DES", context={"key_size": 999})
    assert result.key_size == 56


def test_compound_names_normalize_without_exact_rule(engine: NormalizationEngine):
    result = engine.normalize("AES_128_CBC")
    assert result.algorithm == "AES" and result.mode == "CBC" and result.key_size == 128
    assert result.normalization_confidence == "MEDIUM"
    assert not result.needs_human_review
    legacy = engine.normalize("DES-EDE3-CBC")
    assert legacy.algorithm == "3DES" and legacy.key_size == 168


def test_registry_statuses_reach_the_record(engine: NormalizationEngine):
    weak = engine.normalize("RSA-1024")
    assert weak.key_size == 1024 and weak.nist_designation == "DISALLOWED"
    pqc = engine.normalize("Kyber")
    assert pqc.algorithm_family == "key-agreement"  # model-allowed, not 'pqc'
    assert pqc.nist_designation == "ACCEPTABLE"  # RESTRICTED, not weak
    assert pqc.needs_human_review is False  # registry-known, not junk


def test_context_mode_and_padding_fill_ruleless_results(engine: NormalizationEngine):
    result = engine.normalize("DES-EDE3-CBC", context={"mode": "CBC", "padding": "PKCS5", "purpose": "ENCRYPTION"})
    assert result.mode == "CBC" and result.padding == "PKCS5"
    assert result.purpose == "ENCRYPTION"  # no silent case mangling


def test_unknown_still_flagged_for_review(engine: NormalizationEngine):
    result = engine.normalize("WidgetCipher-42")
    assert result.needs_human_review is True
    assert result.normalization_confidence == "LOW"
    assert result.review_reason is not None


def test_engine_and_processor_agree(engine: NormalizationEngine):
    # one core path: the engine facade and the processor produce the
    # same normalized record for the same input
    for raw, ctx in [
        ("AES/GCM/NoPadding", {"key_size": 128}),
        ("RSA", {"key_size": 3072}),
        ("WidgetCipher-42", {}),
    ]:
        via_engine = engine.normalize(raw, context=ctx)
        via_processor = engine.processor.process(
            raw, purpose=ctx.get("purpose"), key_size=ctx.get("key_size"),
            mode=ctx.get("mode"), padding=ctx.get("padding"),
        )
        assert via_engine.model_dump(exclude={"normalization_timestamp"}) == via_processor.model_dump(
            exclude={"normalization_timestamp"}
        )
        NormalizedCrypto.model_validate(via_engine.model_dump())  # revalidatable end-to-end


def test_normalize_batch_still_enriches(engine: NormalizationEngine):
    records = [
        {
            "finding": {
                "crypto": {"algorithm": "AES_128_CBC", "mode": "CBC", "purpose": "encryption"},
                "source": {"file_path": "a.py", "line_number": 1},
            }
        },
        {"algorithm": "DES", "mode": "ECB"},
    ]
    out = engine.normalize_batch(records)
    assert out[0]["normalized_crypto"]["algorithm"] == "AES"
    assert out[0]["normalized_crypto"]["key_size"] == 128
    assert out[1]["normalized_crypto"]["nist_designation"] == "DISALLOWED"
