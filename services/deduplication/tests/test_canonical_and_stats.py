"""Canonical registry identity for dedup + collapse statistics."""

from __future__ import annotations

from deduplication.core.engine import DeduplicationEngine
from deduplication.core.keys import canonical_dedup_key, canonical_identity_tuple


def _finding(algorithm, scanner, line=10, file_path="src/Pay.java", **extra):
    row = {
        "algorithm": algorithm,
        "purpose": "KEY_EXCHANGE",
        "file_path": file_path,
        "line_number": line,
        "scanner_id": scanner,
        "confidence": "HIGH",
    }
    row.update(extra)
    return row


# --------------------------------------------------------------------------- #
# canonical identity
# --------------------------------------------------------------------------- #

def test_cross_scanner_name_variants_merge():
    findings = [
        _finding("RSA-2048", "java-scanner"),
        _finding("rsa_2048", "python-scanner"),
    ]
    assets = DeduplicationEngine().merge(findings)
    assert len(assets) == 1
    asset = assets[0]
    assert asset["occurrence_count"] == 2
    assert asset["confidence"] == "VERIFIED"  # two distinct scanners agree
    assert asset["scanner_ids"] == ["java-scanner", "python-scanner"]
    assert asset["identity"] == "canonical"


def test_genuinely_different_strengths_stay_distinct():
    assets = DeduplicationEngine().merge(
        [_finding("AES-128", "a"), _finding("AES-256", "a")]
    )
    assert len(assets) == 2


def test_unspecified_size_never_merges_with_specified():
    assets = DeduplicationEngine().merge(
        [_finding("RSA", "a"), _finding("RSA-2048", "b")]
    )
    assert len(assets) == 2  # "RSA" size unknown — could be anything


def test_explicit_key_size_field_merges_with_embedded():
    assets = DeduplicationEngine().merge(
        [_finding("RSA", "a", key_size=2048), _finding("RSA-2048", "b")]
    )
    assert len(assets) == 1


def test_legacy_raw_identity_still_available():
    findings = [_finding("RSA-2048", "a"), _finding("rsa_2048", "b")]
    assets = DeduplicationEngine().merge(findings, canonical=False)
    assert len(assets) == 2
    assert assets[0]["identity"] == "raw"


def test_canonical_key_shared_across_variants():
    assert canonical_dedup_key(_finding("RSA-2048", "a")) == canonical_dedup_key(_finding("rsa_2048", "b"))
    assert canonical_identity_tuple(_finding("AES-256", "a"))[1] == "KEY_EXCHANGE"


# --------------------------------------------------------------------------- #
# stats
# --------------------------------------------------------------------------- #

def test_stats_reflect_collapse_and_verification():
    findings = [
        _finding("RSA-2048", "java-scanner", line=10),
        _finding("rsa_2048", "python-scanner", line=10),
        _finding("AES-256-GCM", "java-scanner", line=20),
        _finding("AES-256-GCM", "java-scanner", line=30),
    ]
    result = DeduplicationEngine().merge_with_stats(findings)
    stats = result["stats"]
    assert stats["findings_in"] == 4
    assert stats["assets_out"] == 3
    assert stats["duplicate_findings_collapsed"] == 1
    assert stats["collapse_rate"] == 0.25
    assert stats["multi_scanner_groups"] == 1
    assert stats["verified_assets"] == 1
    assert stats["cross_scanner_verification_rate"] == round(1 / 3, 3)
    assert stats["distinct_algorithms"] == 2
    assert stats["largest_group"] == 2
    assert stats["identity_mode"] == "canonical"


def test_stats_empty_and_no_duplicates():
    empty = DeduplicationEngine().merge_with_stats([])
    assert empty["assets"] == [] and empty["stats"]["collapse_rate"] == 0.0
    solo = DeduplicationEngine().merge_with_stats([_finding("AES-256-GCM", "a")])
    assert solo["stats"]["duplicate_findings_collapsed"] == 0
    assert solo["stats"]["cross_scanner_verification_rate"] == 0.0


def test_merge_list_api_unchanged():
    assets = DeduplicationEngine().merge([_finding("DES", "a", purpose="ENCRYPTION")])
    assert assets[0]["algorithm"] == "DES"
    assert assets[0]["dedup_key"]
