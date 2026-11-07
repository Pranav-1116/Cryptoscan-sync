"""Evidence-reprocessing contract tests (gap analysis §5 key rule:
reprocess retained evidence without losing the original observation)."""

from __future__ import annotations

import pytest

from shared_models.evidence_reprocessing import (
    REPROCESS_SCHEMA,
    normalize_with, original_fingerprint, original_intact,
    reprocessable, reprocess,
)

RAW = {"snippet": "AES-256-GCM at src/crypto.ts:17", "scanner_id": "s-3",
       "code_origin": "source"}
RECORD = {
    "evidence_id": "ev-1",
    "content_hash": "0123" * 16,
    "finding_data": dict(RAW),
    "normalized_crypto": {"algorithm": "AES", "key_size": None},
    "normalization": {"normalizer_version": "norm-1.0"},
}


def test_reprocessable_reports_the_original_fingerprint():
    check = reprocessable(RECORD)
    assert check["schema"] == REPROCESS_SCHEMA
    assert check["reprocessable"] is True
    assert check["original_fingerprint"].startswith("sha256:")
    assert check["original_fingerprint"] == original_fingerprint(RECORD)


def test_a_record_without_the_original_observation_is_refused():
    with pytest.raises(ValueError):
        reprocessable({**RECORD, "finding_data": None})
    with pytest.raises(ValueError):
        reprocessable({**RECORD, "content_hash": ""})


def test_reprocessing_keeps_the_original_byte_identical():
    out = reprocess(RECORD, normalizer_version="norm-2.0",
                    normalized_crypto={"algorithm": "AES", "key_size": 256})
    verdict = original_intact(RECORD, out)
    assert verdict["original_intact"] is True
    assert verdict["content_hash_match"] is True
    assert verdict["observation_match"] is True
    assert out["finding_data"] == RAW
    assert out["content_hash"] == RECORD["content_hash"]


def test_the_previous_normalization_is_kept_never_lost():
    out = reprocess(RECORD, normalizer_version="norm-2.0",
                    normalized_crypto={"algorithm": "AES", "key_size": 256})
    assert out["normalized_crypto"] == {"algorithm": "AES", "key_size": 256}
    assert out["normalization"]["normalizer_version"] == "norm-2.0"
    assert out["normalization"]["reprocessed_at"]
    superseded = out["superseded_normalizations"]
    assert len(superseded) == 1
    assert superseded[0]["normalized_crypto"] == {"algorithm": "AES", "key_size": None}
    assert superseded[0]["normalization"]["normalizer_version"] == "norm-1.0"


def test_reprocessing_twice_builds_history_not_overwrites():
    once = reprocess(RECORD, normalizer_version="norm-2.0",
                     normalized_crypto={"algorithm": "AES"})
    twice = reprocess(once, normalizer_version="norm-3.0",
                      normalized_crypto={"algorithm": "AES-256-GCM"})
    assert len(twice["superseded_normalizations"]) == 2
    versions = [twice["normalization"]["normalizer_version"]] + [
        row["normalization"]["normalizer_version"]
        for row in twice["superseded_normalizations"]]
    assert "norm-1.0" in versions and "norm-2.0" in versions and "norm-3.0" in versions


def test_a_mutating_normalizer_cannot_touch_the_record_original():
    def tamper(raw):
        raw["snippet"] = "edited"
        return {"algorithm": "AES"}

    out = normalize_with(RECORD, normalizer_version="norm-2.0", normalizer=tamper)
    # the normalizer only ever held a frozen copy — the retained original,
    # its hash and the record itself are untouched (structural, not promised)
    assert RECORD["finding_data"] == RAW
    assert out["finding_data"] == RAW
    assert original_intact(RECORD, out)["original_intact"] is True


def test_an_unversioned_normalization_is_refused():
    with pytest.raises(ValueError):
        reprocess(RECORD, normalizer_version="", normalized_crypto={})


def test_original_intact_detects_a_changed_original():
    tampered = {**RECORD, "finding_data": {"snippet": "different"}}
    verdict = original_intact(RECORD, tampered)
    assert verdict["original_intact"] is False
    assert verdict["observation_match"] is False


def test_normalize_with_reproduces_from_the_original_only():
    seen = []

    def normalizer(raw):
        seen.append(raw)
        return {"algorithm": "AES", "key_size": 256,
                "derived_from": raw["snippet"]}

    out = normalize_with(RECORD, normalizer_version="norm-2.0",
                         normalizer=normalizer)
    assert seen == [RAW], "the normalizer sees the original, not the old facts"
    assert out["normalized_crypto"]["derived_from"] == RAW["snippet"]
    assert out["normalization"]["normalizer_version"] == "norm-2.0"
